#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0

"""Benchmarks for page_pool netlink, queue reset, and devmem control paths."""

import errno
import os
import sys
import time

THIS_DIR = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(THIS_DIR, "../"))
# pylint: disable-next=wrong-import-position,import-error,no-name-in-module
from lib.py import (
    CmdExitFailure,
    EthtoolFamily,
    KsftSkipEx,
    NetdevFamily,
    NetdevSimDev,
    NlError,
    cmd,
    create_udmabuf,
    defer,
    devmem_bind,
    ip,
    ksft_eq,
    ksft_exit,
    ksft_metric,
    ksft_pr,
    ksft_run,
)

NL_ITERS = 200
RESET_ITERS = 20
DEVMEM_BIND_ITERS = 5


def _require_netdevsim() -> None:
    if os.geteuid() != 0:
        raise KsftSkipEx("netdevsim benchmarks require root privileges")
    if not os.path.exists("/sys/bus/netdevsim"):
        try:
            cmd("modprobe netdevsim")
        except CmdExitFailure as exc:
            raise KsftSkipEx(f"netdevsim module unavailable: {exc}") from exc
    if not os.path.exists("/sys/kernel/debug/netdevsim"):
        raise KsftSkipEx("/sys/kernel/debug/netdevsim unavailable (debugfs)")


def _measure_us(fn, iters: int) -> float:
    start = time.perf_counter_ns()
    for _ in range(iters):
        fn()
    return (time.perf_counter_ns() - start) / (iters * 1000.0)


def bench_nl_get_and_stats(nf) -> None:
    """Benchmark netdev netlink page-pool-get and page-pool-stats-get."""
    _require_netdevsim()
    nsimdev = NetdevSimDev(queue_count=4)
    defer(nsimdev.remove)
    nsim = nsimdev.nsims[0]
    ip(f"link set dev {nsim.ifname} up")

    pools = nf.page_pool_get({"ifindex": nsim.ifindex}, dump=True)
    ksft_eq(len(pools), 4)
    pp_id = pools[0]["id"]
    ksft_eq(nf.page_pool_get({"id": pp_id})["id"], pp_id)

    get_doit = _measure_us(lambda: nf.page_pool_get({"id": pp_id}), NL_ITERS)
    get_dump = _measure_us(
        lambda: nf.page_pool_get({"ifindex": nsim.ifindex}, dump=True),
        NL_ITERS,
    )
    ksft_metric("nl-pp-get-doit-us", round(get_doit, 2), goal="lower")
    ksft_metric("nl-pp-get-dump-us", round(get_dump, 2), goal="lower")

    try:
        stats = nf.page_pool_stats_get({"info": {"id": pp_id}})
    except NlError as exc:
        if exc.error == errno.EOPNOTSUPP:
            ksft_pr("page-pool-stats-get unsupported (CONFIG_PAGE_POOL_STATS=n)")
            return
        raise

    ksft_eq(stats["info"]["id"], pp_id)
    stats_doit = _measure_us(
        lambda: nf.page_pool_stats_get({"info": {"id": pp_id}}),
        NL_ITERS,
    )
    stats_dump = _measure_us(
        lambda: nf.page_pool_stats_get({"info": {"ifindex": nsim.ifindex}},
                                       dump=True),
        NL_ITERS,
    )
    ksft_metric("nl-pp-stats-doit-us", round(stats_doit, 2), goal="lower")
    ksft_metric("nl-pp-stats-dump-us", round(stats_dump, 2), goal="lower")


def bench_queue_reset(nf) -> None:
    """Benchmark netdevsim RX queue reset modes 0..3."""
    _require_netdevsim()
    nsimdev = NetdevSimDev(queue_count=4)
    defer(nsimdev.remove)
    nsim = nsimdev.nsims[0]
    ip(f"link set dev {nsim.ifname} up")

    def reset_all_modes():
        for mode in range(4):
            nsim.dfs_write("queue_reset", f"1 {mode}")

    us_per_reset = _measure_us(reset_all_modes, RESET_ITERS) / 4.0
    ksft_metric("nsim-queue-reset-us", round(us_per_reset, 2), goal="lower")

    pools = nf.page_pool_get({"ifindex": nsim.ifindex}, dump=True)
    ksft_eq(len(pools), 4)


def bench_devmem_bind_and_reset(nf) -> None:
    """Benchmark udmabuf RX devmem bind/unbind and devmem queue reset."""
    _require_netdevsim()
    dmabuf_fd = create_udmabuf()
    defer(os.close, dmabuf_fd)
    nsimdev = NetdevSimDev(queue_count=2)
    defer(nsimdev.remove)
    nsim = nsimdev.nsims[0]

    ip(f"link set dev {nsim.ifname} up")
    with EthtoolFamily() as ef:
        ef.rings_set({"header": {"dev-index": nsim.ifindex},
                      "tcp-data-split": "enabled"})

    bind_attrs = {
        "ifindex": nsim.ifindex,
        "fd": dmabuf_fd,
        "queues": [{"id": 1, "type": "rx"}],
    }

    total_ns = 0
    for _ in range(DEVMEM_BIND_ITERS):
        nf_priv = NetdevFamily()
        try:
            start = time.perf_counter_ns()
            devmem_bind(nf_priv.bind_rx, bind_attrs)
            nf_priv.close()
            total_ns += time.perf_counter_ns() - start
        finally:
            nf_priv.close()

    bind_us = total_ns / (DEVMEM_BIND_ITERS * 1000.0)
    ksft_metric("devmem-bind-unbind-us", round(bind_us, 2), goal="lower")

    with NetdevFamily() as nf_priv:
        devmem_bind(nf_priv.bind_rx, bind_attrs)

        def reset_devmem_modes():
            for mode in range(4):
                nsim.dfs_write("queue_reset", f"1 {mode}")

        reset_us = _measure_us(reset_devmem_modes, RESET_ITERS) / 4.0
        ksft_metric("devmem-queue-reset-us", round(reset_us, 2), goal="lower")
        pools = nf.page_pool_get({"ifindex": nsim.ifindex}, dump=True)
        ksft_eq(len(pools), 2)


def main() -> None:
    """Run netdevsim page_pool benchmarks via kselftest."""
    with NetdevFamily() as nf:
        ksft_run(
            [
                bench_nl_get_and_stats,
                bench_queue_reset,
                bench_devmem_bind_and_reset,
            ],
            args=(nf,),
        )
    ksft_exit()


if __name__ == "__main__":
    main()
