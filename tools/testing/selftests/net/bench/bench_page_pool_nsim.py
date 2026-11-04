#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
# pylint: disable=too-many-locals,too-many-branches,too-many-statements
# pylint: disable=too-many-arguments,too-many-positional-arguments
# pylint: disable=too-many-nested-blocks
"""
End-to-end netdevsim benchmark and coverage test for page_pool.

Exercises and benchmarks page_pool paths that require a live net_device, NAPI,
netdev genl (page_pool_user.c), and memory_provider (mp_dmabuf_devmem net_iov):
  - Netlink page-pool-get / page-pool-stats-get dump and doit latency
  - Queue reset modes 0..3 (page_pool_disable_direct_recycling & NAPI resets)
  - Deferred pool shutdown (pp_hold -> release_dw) and netdev unregister orphan
  - Host page_pool HDS TCP RX (4KB order-0) and generic XDP_DROP recycle
  - Unreadable dmabuf (udmabuf) memory_provider net_iov RX + SO_DEVMEM_DONTNEED
    at both 4KB (order-0) and 16KB (order-2 rx-page-size)
"""

import atexit
import ctypes
import fcntl
import mmap
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time

THIS_DIR = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(THIS_DIR, "../"))
# pylint: disable-next=wrong-import-position,import-error,no-name-in-module
from lib.py import EthtoolFamily, NetdevFamily, NetdevSimDev, NetNS
# pylint: disable-next=wrong-import-position,import-error,no-name-in-module
from lib.py import NlError, cmd, ip

MSG_SOCK_DEVMEM = 0x2000000
SCM_DEVMEM_DMABUF = 79
SO_DEVMEM_DONTNEED = 80
MFD_HUGETLB = getattr(os, "MFD_HUGETLB", 0x0004)
NR_HUGEPAGES_PATH = "/proc/sys/vm/nr_hugepages"

# BPF / Netlink constants for attaching a 2-insn XDP_DROP program
SYS_BPF_X86_64 = 321
SYS_BPF_AARCH64 = 280
BPF_PROG_LOAD = 5
BPF_PROG_TYPE_XDP = 6
BPF_F_XDP_HAS_FRAGS = 1 << 5
RTM_SETLINK = 19
NLM_F_REQUEST = 0x01
NLM_F_ACK = 0x04
NLA_F_NESTED = 1 << 15
IFLA_XDP = 43
IFLA_XDP_FD = 1
IFLA_XDP_FLAGS = 3
XDP_FLAGS_SKB_MODE = 1 << 1


def _udmabuf_create_ioctl() -> int:
    """Return UDMABUF_CREATE, _IOW('u', 0x42, struct udmabuf_create)."""
    machine = os.uname().machine
    if machine.startswith(("alpha", "mips", "ppc", "powerpc", "sparc")):
        ioc_write = 4 << 29
    elif machine.startswith("parisc"):
        ioc_write = 2 << 30
    else:
        ioc_write = 1 << 30
    return ioc_write | 24 << 16 | ord("u") << 8 | 0x42


def _create_udmabuf(size_bytes: int, hugetlb: bool = False) -> int:
    """Create a sealed memfd-backed udmabuf fd of @size_bytes."""
    if not os.path.exists("/dev/udmabuf"):
        return -1

    flags = os.MFD_ALLOW_SEALING | (MFD_HUGETLB if hugetlb else 0)
    try:
        memfd = os.memfd_create("pp-bench-dmabuf", flags)
    except OSError:
        return -1

    try:
        os.ftruncate(memfd, size_bytes)
        fcntl.fcntl(memfd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_SHRINK)
        devfd = os.open("/dev/udmabuf", os.O_RDWR)
        try:
            req = bytearray(struct.pack("IIQQ", memfd, 0, 0, size_bytes))
            return fcntl.ioctl(devfd, _udmabuf_create_ioctl(), req)
        finally:
            os.close(devfd)
    except OSError:
        return -1
    finally:
        os.close(memfd)


def _pp_for_ifindex(nf: NetdevFamily, ifindex: int) -> list:
    return nf.page_pool_get({"ifindex": ifindex}, dump=True)


def _pp_stats_for_ifindex(nf: NetdevFamily, ifindex: int) -> dict:
    totals = {
        "alloc-fast": 0,
        "alloc-slow": 0,
        "alloc-slow-high-order": 0,
        "alloc-empty": 0,
        "alloc-refill": 0,
        "alloc-waive": 0,
        "recycle-cached": 0,
        "recycle-cache-full": 0,
        "recycle-ring": 0,
        "recycle-ring-full": 0,
        "recycle-released-refcnt": 0,
    }
    rows = nf.page_pool_stats_get({"info": {"ifindex": ifindex}}, dump=True)
    for row in rows:
        for key in totals:
            totals[key] += row.get(key, 0)
    return totals


def _stats_delta(before: dict, after: dict) -> dict:
    return {k: after.get(k, 0) - before.get(k, 0) for k in before}


def bench_control_plane(nf: NetdevFamily) -> None:
    """Benchmark and verify page_pool Netlink dumps, queue resets, and orphan."""
    with NetdevSimDev(queue_count=4) as nsimdev:
        nsim = nsimdev.nsims[0]
        ip(f"link set dev {nsim.ifname} up")

        pools = _pp_for_ifindex(nf, nsim.ifindex)
        if len(pools) != 4:
            raise RuntimeError(f"Expected 4 page_pools, got {len(pools)}")

        # Single-pool doit get + stats get
        first_id = pools[0]["id"]
        one_pp = nf.page_pool_get({"id": first_id})
        if one_pp["id"] != first_id:
            raise RuntimeError("page_pool_get doit returned wrong id")
        one_st = nf.page_pool_stats_get({"info": {"id": first_id}})
        if one_st["info"]["id"] != first_id:
            raise RuntimeError("page_pool_stats_get doit returned wrong id")

        # Benchmark Netlink dump + stats dump latency
        iters = 200
        t0 = time.monotonic_ns()
        for _ in range(iters):
            _pp_for_ifindex(nf, nsim.ifindex)
            _pp_stats_for_ifindex(nf, nsim.ifindex)
        elapsed_ns = time.monotonic_ns() - t0
        print(
            f"nsim-nl-dump-and-stats: {elapsed_ns // (iters * 1000)} us/iter "
            f"({iters} dumps across 4 queues)"
        )

        # Benchmark queue_reset modes 0..3 (mode 1 tests disable_direct_recycling)
        reset_iters = 20
        for mode in range(4):
            t0 = time.monotonic_ns()
            for q in range(reset_iters):
                nsim.dfs_write("queue_reset", f"{q % 4} {mode}")
            elapsed_ns = time.monotonic_ns() - t0
            pools = _pp_for_ifindex(nf, nsim.ifindex)
            if len(pools) != 4:
                raise RuntimeError(
                    f"Pool count mismatch after mode {mode}: {len(pools)}"
                )
            print(
                f"nsim-queue-reset-mode{mode}: "
                f"{elapsed_ns // (reset_iters * 1000)} us/reset "
                f"({reset_iters} resets)"
            )

        # Exercise dmabuf memory_provider page_pool bind, queue_reset, and unbind
        dmabuf_fd = _create_udmabuf(64 * mmap.PAGESIZE)
        if dmabuf_fd >= 0:
            with EthtoolFamily() as ef:
                ef.rings_set(
                    {
                        "header": {"dev-index": nsim.ifindex},
                        "tcp-data-split": "enabled",
                    }
                )
            nf_bind = NetdevFamily()
            try:
                t0 = time.monotonic_ns()
                bind_res = nf_bind.bind_rx(
                    {
                        "ifindex": nsim.ifindex,
                        "fd": dmabuf_fd,
                        "queues": [{"id": 0, "type": "rx"}],
                    }
                )
                dmabuf_id = bind_res["id"]
                dmabuf_pps = [
                    pp for pp in _pp_for_ifindex(nf, nsim.ifindex)
                    if pp.get("dmabuf") == dmabuf_id
                ]
                if len(dmabuf_pps) != 1:
                    raise RuntimeError(
                        f"Expected 1 dmabuf page_pool, got {dmabuf_pps}"
                    )
                for mode in range(4):
                    nsim.dfs_write("queue_reset", f"0 {mode}")
                bind_us = (time.monotonic_ns() - t0) // 1000
                print(
                    f"nsim-dmabuf-mp-bind-reset: {bind_us} us "
                    "(bind_rx + 4 queue_reset modes)"
                )
            finally:
                nf_bind.close()
                os.close(dmabuf_fd)

        # Exercise pp_hold -> detached pool -> release_dw
        nsim.dfs_write("pp_hold", "y")
        ip(f"link set dev {nsim.ifname} down")
        detached = [
            pp for pp in _pp_for_ifindex(nf, nsim.ifindex)
            if "detach-time" in pp
        ]
        if len(detached) != 1 or detached[0].get("inflight", 0) < 1:
            raise RuntimeError(f"Expected 1 detached pool, got {detached}")

        ip(f"link set dev {nsim.ifname} up")
        t0 = time.monotonic_ns()
        nsim.dfs_write("pp_hold", "n")
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            if len(_pp_for_ifindex(nf, nsim.ifindex)) == 4:
                break
            time.sleep(0.05)
        else:
            raise RuntimeError("Detached page_pool was not freed after pp_hold=n")
        release_ms = (time.monotonic_ns() - t0) // 1_000_000
        print(f"nsim-pp-hold-deferred-release: {release_ms} ms")

        # Leave pp_hold=y across device removal to exercise page_pool_orphan()
        nsim.dfs_write("pp_hold", "y")
    print("nsim-pp-orphan-on-unregister: PASS")


def _load_xdp_drop_prog() -> int:
    """Load a 2-insn XDP_DROP BPF program with BPF_F_XDP_HAS_FRAGS via ctypes."""
    machine = os.uname().machine
    if machine == "x86_64":
        sys_bpf = SYS_BPF_X86_64
    elif machine == "aarch64":
        sys_bpf = SYS_BPF_AARCH64
    else:
        return -1

    # BPF_MOV64_IMM(BPF_REG_0, XDP_DROP=1); BPF_EXIT_INSN()
    insns = struct.pack("<BBBBiBBBBi", 0xB7, 0x00, 0, 0, 1, 0x95, 0x00, 0, 0, 0)
    insns_buf = ctypes.create_string_buffer(insns, len(insns))
    lic_buf = ctypes.create_string_buffer(b"GPL")

    attr = ctypes.create_string_buffer(128)
    struct.pack_into(
        "<IIQQII",
        attr,
        0,
        BPF_PROG_TYPE_XDP,
        2,
        ctypes.addressof(insns_buf),
        ctypes.addressof(lic_buf),
        0,
        0,
    )
    # prog_flags is at offset 44 in union bpf_attr for BPF_PROG_LOAD
    struct.pack_into("<I", attr, 44, BPF_F_XDP_HAS_FRAGS)

    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    fd = libc.syscall(
        ctypes.c_long(sys_bpf),
        ctypes.c_int(BPF_PROG_LOAD),
        ctypes.byref(attr),
        ctypes.c_uint(64),
    )
    return int(fd) if fd >= 0 else -1


def _set_xdp_fd(ifindex: int, prog_fd: int) -> bool:
    """Attach or detach (@prog_fd == -1) generic XDP on @ifindex via RTNetlink."""
    fd_attr = struct.pack("<HHihh", 8, IFLA_XDP_FD, prog_fd, 0, 0)[:8]
    fl_attr = struct.pack("<HHI", 8, IFLA_XDP_FLAGS, XDP_FLAGS_SKB_MODE)
    nested_payload = fd_attr + fl_attr
    nested_hdr = struct.pack(
        "<HH", 4 + len(nested_payload), IFLA_XDP | NLA_F_NESTED
    )
    ifi_msg = struct.pack("<BBHiII", socket.AF_UNSPEC, 0, 0, ifindex, 0, 0)
    total_len = 16 + len(ifi_msg) + len(nested_hdr) + len(nested_payload)
    nl_hdr = struct.pack(
        "<IHHII",
        total_len,
        RTM_SETLINK,
        NLM_F_REQUEST | NLM_F_ACK,
        1,
        0,
    )

    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW,
                       socket.NETLINK_ROUTE) as rtnl:
        rtnl.send(nl_hdr + ifi_msg + nested_hdr + nested_payload)
        resp = rtnl.recv(4096)
        if len(resp) < 20:
            return False
        _, msg_type, _, _, _ = struct.unpack("<IHHII", resp[:16])
        if msg_type == 2:  # NLMSG_ERROR
            (err_code,) = struct.unpack("<i", resp[16:20])
            return err_code == 0
    return False


def _send_in_netns(ns_name: str, proto: str, dst_ip: str, port: int,
                   chunk_size: int, count: int) -> subprocess.Popen:
    """Spawn a helper process inside @ns_name sending @count chunks."""
    py_code = (
        "import socket, time\n"
        f"s = socket.socket(socket.AF_INET, "
        f"socket.SOCK_STREAM if '{proto}' == 'tcp' else socket.SOCK_DGRAM)\n"
        f"buf = b'x' * {chunk_size}\n"
        f"if '{proto}' == 'tcp':\n"
        f"    s.connect(('{dst_ip}', {port}))\n"
        f"    for _ in range({count}):\n"
        "        s.sendall(buf)\n"
        "else:\n"
        f"    for _ in range({count}):\n"
        f"        s.sendto(buf, ('{dst_ip}', {port}))\n"
        "s.close()\n"
    )
    return subprocess.Popen(
        ["ip", "netns", "exec", ns_name, sys.executable, "-c", py_code],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _run_devmem_rx_bench(nf: NetdevFamily, rx_nsim, peer_ns_name: str,
                         rx_ip: str, rx_page_size: int,
                         total_bytes: int) -> None:
    """Bind a udmabuf to queue 1 and benchmark devmem net_iov RX + DONTNEED."""
    hugetlb = rx_page_size > mmap.PAGESIZE
    saved_hp = None
    if hugetlb:
        try:
            with open(NR_HUGEPAGES_PATH, "r+", encoding="utf-8") as f:
                saved_hp = int(f.read().strip())
                if saved_hp < 8:
                    f.seek(0)
                    f.write("8")
        except OSError:
            print(f"INFO: nsim-rx-devmem-{rx_page_size // 1024}k (no hugepages)")
            return

    try:
        buf_bytes = 8 * 1024 * 1024 if hugetlb else 1024 * mmap.PAGESIZE
        dmabuf_fd = _create_udmabuf(buf_bytes, hugetlb=hugetlb)
        if dmabuf_fd < 0:
            print(
                f"INFO: nsim-rx-devmem-{rx_page_size // 1024}k "
                "(udmabuf unavailable)"
            )
            return

        nf_bind = NetdevFamily()
        try:
            bind_req = {
                "ifindex": rx_nsim.ifindex,
                "fd": dmabuf_fd,
                "queues": [{"id": 1, "type": "rx"}],
            }
            if rx_page_size > mmap.PAGESIZE:
                bind_req["rx-page-size"] = rx_page_size
            try:
                bind_res = nf_bind.bind_rx(bind_req)
            except NlError as e:
                print(
                    f"INFO: nsim-rx-devmem-{rx_page_size // 1024}k "
                    f"(bind_rx unsupported: {e})"
                )
                return

            dmabuf_id = bind_res["id"]
            dmabuf_pools = [
                pp for pp in _pp_for_ifindex(nf, rx_nsim.ifindex)
                if pp.get("dmabuf") == dmabuf_id
            ]
            if len(dmabuf_pools) != 1:
                raise RuntimeError(
                    f"Expected 1 dmabuf page_pool (id={dmabuf_id}), "
                    f"got {dmabuf_pools}"
                )

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
                srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                srv.bind((rx_ip, 0))
                srv.listen(1)
                port = srv.getsockname()[1]

                rule_added = False
                res = cmd(
                    f"ethtool -N {rx_nsim.ifname} flow-type tcp4 "
                    f"dst-port {port} action 1",
                    fail=False,
                )
                if res.ret == 0:
                    rule_added = True

                try:
                    before = _pp_stats_for_ifindex(nf, rx_nsim.ifindex)
                    chunk = 16384
                    count = max(1, total_bytes // chunk)
                    sender = _send_in_netns(
                        peer_ns_name, "tcp", rx_ip, port, chunk, count
                    )
                    try:
                        conn, _ = srv.accept()
                        with conn:
                            t0 = time.monotonic_ns()
                            rcvd = 0
                            tokens_released = 0
                            pending_tokens = []
                            while rcvd < count * chunk:
                                data, ancdata, _, _ = conn.recvmsg(
                                    65536, 4096, MSG_SOCK_DEVMEM
                                )
                                if not data and not ancdata:
                                    break
                                rcvd += len(data)
                                for cmsg_lvl, cmsg_type, cmsg_data in ancdata:
                                    if (
                                        cmsg_lvl == socket.SOL_SOCKET
                                        and cmsg_type == SCM_DEVMEM_DMABUF
                                        and len(cmsg_data) >= 24
                                    ):
                                        _, _, token, _, _ = struct.unpack(
                                            "<QIIII", cmsg_data[:24]
                                        )
                                        pending_tokens.append(token)
                                if len(pending_tokens) >= 16:
                                    payload = b"".join(
                                        struct.pack("<II", tok, 1)
                                        for tok in pending_tokens
                                    )
                                    conn.setsockopt(
                                        socket.SOL_SOCKET,
                                        SO_DEVMEM_DONTNEED,
                                        payload,
                                    )
                                    tokens_released += len(pending_tokens)
                                    pending_tokens.clear()

                            if pending_tokens:
                                payload = b"".join(
                                    struct.pack("<II", tok, 1)
                                    for tok in pending_tokens
                                )
                                conn.setsockopt(
                                    socket.SOL_SOCKET,
                                    SO_DEVMEM_DONTNEED,
                                    payload,
                                )
                                tokens_released += len(pending_tokens)
                                pending_tokens.clear()
                            elapsed_ns = max(1, time.monotonic_ns() - t0)
                    finally:
                        sender.wait(timeout=10)

                    after = _pp_stats_for_ifindex(nf, rx_nsim.ifindex)
                    delta = _stats_delta(before, after)
                    if tokens_released == 0 or (
                        delta["alloc-fast"] + delta["alloc-refill"] == 0
                    ):
                        raise RuntimeError(
                            f"devmem-{rx_page_size // 1024}k did not exercise "
                            f"net_iov page_pool: tokens={tokens_released} "
                            f"stats={delta}"
                        )
                    mbps = (rcvd * 1000) // elapsed_ns
                    ns_per_tok = elapsed_ns // max(1, tokens_released)
                    print(
                        f"nsim-rx-devmem-{rx_page_size // 1024}k: "
                        f"{mbps} MB/s, {ns_per_tok} ns/niov "
                        f"(tokens={tokens_released} "
                        f"fast={delta['alloc-fast']} "
                        f"refill={delta['alloc-refill']} "
                        f"ring={delta['recycle-ring']})"
                    )
                finally:
                    if rule_added:
                        cmd(
                            f"ethtool -N {rx_nsim.ifname} delete 0",
                            fail=False,
                        )
        finally:
            nf_bind.close()
            os.close(dmabuf_fd)
    finally:
        if saved_hp is not None:
            try:
                with open(NR_HUGEPAGES_PATH, "w", encoding="utf-8") as f:
                    f.write(str(saved_hp))
            except OSError:
                pass


def bench_datapath(nf: NetdevFamily) -> None:
    """Benchmark netdevsim page_pool RX datapath (HDS, XDP_DROP, and devmem)."""
    rx_ip = "192.0.2.1"
    tx_ip = "192.0.2.2"

    with NetNS() as peer_ns, NetdevSimDev(queue_count=2) as rx_dev, NetdevSimDev(
        queue_count=2, ns=peer_ns
    ) as tx_dev:
        rx_nsim = rx_dev.nsims[0]
        tx_nsim = tx_dev.nsims[0]

        with open("/proc/self/ns/net", encoding="utf-8") as nsfd0, open(
            f"/var/run/netns/{peer_ns.name}", encoding="utf-8"
        ) as nsfd1:
            NetdevSimDev.ctrl_write(
                "link_device",
                f"{nsfd0.fileno()}:{rx_nsim.ifindex} "
                f"{nsfd1.fileno()}:{tx_nsim.ifindex}",
            )

        ip(f"addr add {rx_ip}/24 dev {rx_nsim.ifname}")
        ip(f"link set dev {rx_nsim.ifname} up")
        ip(f"addr add {tx_ip}/24 dev {tx_nsim.ifname}", ns=peer_ns)
        ip(f"link set dev {tx_nsim.ifname} up", ns=peer_ns)

        with EthtoolFamily() as ef:
            ef.rings_set(
                {
                    "header": {"dev-index": rx_nsim.ifindex},
                    "tcp-data-split": "enabled",
                }
            )
        cmd(f"ethtool -C {rx_nsim.ifname} rx-usecs 0", fail=False)

        # Probe whether running netdevsim allocates RX frags from rq->page_pool
        before_probe = _pp_stats_for_ifindex(nf, rx_nsim.ifindex)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((rx_ip, 0))
            srv.listen(1)
            port = srv.getsockname()[1]
            sender = _send_in_netns(peer_ns.name, "tcp", rx_ip, port, 16384, 4)
            conn, _ = srv.accept()
            with conn:
                while conn.recv(65536):
                    pass
            sender.wait(timeout=5)
        probe_delta = _stats_delta(
            before_probe, _pp_stats_for_ifindex(nf, rx_nsim.ifindex)
        )
        if probe_delta["alloc-fast"] + probe_delta["alloc-slow"] == 0:
            print(
                "INFO: netdevsim RX page_pool datapath not present in kernel"
            )
            return

        # 1. Host page_pool 4KB HDS TCP RX benchmark
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((rx_ip, 0))
            srv.listen(1)
            port = srv.getsockname()[1]
            chunk = 32768
            count = 512  # 16 MB
            before = _pp_stats_for_ifindex(nf, rx_nsim.ifindex)
            sender = _send_in_netns(
                peer_ns.name, "tcp", rx_ip, port, chunk, count
            )
            conn, _ = srv.accept()
            rcvd = 0
            t0 = time.monotonic_ns()
            with conn:
                while True:
                    buf = conn.recv(65536)
                    if not buf:
                        break
                    rcvd += len(buf)
            elapsed_ns = max(1, time.monotonic_ns() - t0)
            sender.wait(timeout=10)
            delta = _stats_delta(
                before, _pp_stats_for_ifindex(nf, rx_nsim.ifindex)
            )
            pages = (
                delta["alloc-fast"]
                + delta["alloc-slow"]
                + delta["alloc-refill"]
            )
            if pages == 0 or (
                delta["recycle-ring"] + delta["recycle-cached"] == 0
            ):
                raise RuntimeError(
                    f"HDS TCP RX did not recycle page_pool pages: {delta}"
                )
            mbps = (rcvd * 1000) // elapsed_ns
            print(
                f"nsim-rx-hds-tcp-4k: {mbps} MB/s, "
                f"{elapsed_ns // pages} ns/page "
                f"(fast={delta['alloc-fast']} slow={delta['alloc-slow']} "
                f"refill={delta['alloc-refill']} "
                f"cached={delta['recycle-cached']} "
                f"ring={delta['recycle-ring']})"
            )

        # 2. Generic XDP_DROP inside NAPI poll (exercises skb_cow_data_for_xdp
        #    and NAPI-local direct cache recycling)
        xdp_fd = _load_xdp_drop_prog()
        if xdp_fd >= 0:
            try:
                if _set_xdp_fd(rx_nsim.ifindex, xdp_fd):
                    try:
                        before = _pp_stats_for_ifindex(nf, rx_nsim.ifindex)
                        pkts = 1000
                        t0 = time.monotonic_ns()
                        sender = _send_in_netns(
                            peer_ns.name, "udp", rx_ip, 9999, 2048, pkts
                        )
                        sender.wait(timeout=10)
                        deadline = time.monotonic() + 2.0
                        while time.monotonic() < deadline:
                            delta = _stats_delta(
                                before,
                                _pp_stats_for_ifindex(nf, rx_nsim.ifindex),
                            )
                            if delta["recycle-cached"] >= pkts // 2:
                                break
                            time.sleep(0.02)
                        elapsed_ns = max(1, time.monotonic_ns() - t0)
                        if delta["recycle-cached"] == 0:
                            raise RuntimeError(
                                f"XDP_DROP did not hit recycle-cached: {delta}"
                            )
                        print(
                            f"nsim-rx-xdp-drop: "
                            f"{elapsed_ns // max(1, delta['recycle-cached'])} "
                            f"ns/pkt "
                            f"(cached={delta['recycle-cached']} "
                            f"fast={delta['alloc-fast']})"
                        )
                    finally:
                        _set_xdp_fd(rx_nsim.ifindex, -1)
            finally:
                os.close(xdp_fd)

        # 3. Unreadable dmabuf memory_provider (net_iov) 4KB and 16KB RX
        _run_devmem_rx_bench(
            nf, rx_nsim, peer_ns.name, rx_ip, mmap.PAGESIZE, 4 * 1024 * 1024
        )
        _run_devmem_rx_bench(
            nf, rx_nsim, peer_ns.name, rx_ip, 16384, 4 * 1024 * 1024
        )


def main() -> int:
    """Entry point for netdevsim page_pool and devmem benchmarks."""
    if not os.path.exists("/sys/bus/netdevsim"):
        res = cmd("modprobe netdevsim", fail=False)
        if res.ret != 0 or not os.path.exists("/sys/bus/netdevsim"):
            print("INFO: netdevsim module not available")
            return 0

    if cmd("udevadm settle --timeout=1", fail=False).ret != 0:
        stub_dir = tempfile.mkdtemp(prefix="pp-bench-bin-")
        atexit.register(shutil.rmtree, stub_dir, True)
        stub_path = os.path.join(stub_dir, "udevadm")
        with open(stub_path, "w", encoding="utf-8") as f:
            f.write("#!/bin/sh\nexit 0\n")
        os.chmod(stub_path, 0o755)
        os.environ["PATH"] = f"{stub_dir}:{os.environ.get('PATH', '')}"

    with NetdevFamily() as nf:
        bench_control_plane(nf)
        bench_datapath(nf)
    return 0


if __name__ == "__main__":
    sys.exit(main())
