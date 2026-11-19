# SPDX-License-Identifier: GPL-2.0

"""
Helpers for udmabuf creation and devmem netlink bindings in netdev selftests.
"""

import errno
import fcntl
import mmap
import os
import struct

from .ksft import KsftSkipEx
from .ynl import NlError


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


def create_udmabuf(num_pages: int = 64) -> int:
    """Create a sealed memfd-backed udmabuf fd for devmem tests."""
    try:
        devfd = os.open("/dev/udmabuf", os.O_RDWR)
    except OSError as e:
        if e.errno in (errno.ENOENT, errno.ENODEV):
            raise KsftSkipEx("/dev/udmabuf is not available") from e
        raise

    try:
        size = num_pages * mmap.PAGESIZE
        memfd = os.memfd_create("devmem-ksft", os.MFD_ALLOW_SEALING)
        try:
            os.ftruncate(memfd, size)
            fcntl.fcntl(memfd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_SHRINK)
            req = bytearray(struct.pack("IIQQ", memfd, 0, 0, size))
            return fcntl.ioctl(devfd, _udmabuf_create_ioctl(), req)
        finally:
            os.close(memfd)
    finally:
        os.close(devfd)


def devmem_bind(bind, attrs):
    """Run a devmem bind op, skip the test if the device can't do devmem."""
    try:
        return bind(attrs)
    except NlError as e:
        if e.error == errno.EOPNOTSUPP:
            raise KsftSkipEx(f"devmem binding not supported: {e}") from e
        raise
