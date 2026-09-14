#!/usr/bin/env python3
"""
bpf_syscall.py -- direct bpf(2) syscall wrapper for the PFCP agent's
hot-path BPF map writes.

Motivation (Section: same-testbed eUPF comparison): the original agent.py
issued every BPF map write as a freshly spawned `sudo bpftool map update`
subprocess. Measured directly on the native-XDP testbed, that costs
~11-15ms per call -- sudo/exec overhead, unrelated to the cost of the
underlying bpf_map_update_elem() call itself (measured separately, at the
syscall level, at ~2-3us). Since the agent is already a long-running
process (it serves /metrics and /ruleupdate over HTTP), there is no
reason to pay a fresh subprocess-spawn cost on every rule install --
this module calls the bpf() syscall directly via ctypes, exactly the
mechanism libbpf/cilium-ebpf use internally, just without linking a C
library. This is the same class of fix as eUPF's own control plane
(a long-lived Go process calling cilium/ebpf's map.Put() in-process).

Only BPF_OBJ_GET, BPF_MAP_UPDATE_ELEM, and BPF_MAP_DELETE_ELEM are
implemented -- the operations actually on the rule-install hot path.
Bulk reads (used only for /metrics scraping, not benchmarked) continue
to go through bpftool's map dump, which is not performance-sensitive
here.
"""
import ctypes
import os

_libc = ctypes.CDLL("libc.so.6", use_errno=True)

__NR_bpf = 321  # x86_64; see /usr/include/x86_64-linux-gnu/asm/unistd_64.h

BPF_MAP_LOOKUP_ELEM = 1
BPF_MAP_UPDATE_ELEM = 2
BPF_MAP_DELETE_ELEM = 3
BPF_OBJ_GET = 7

BPF_ANY = 0
BPF_NOEXIST = 1
BPF_EXIST = 2


class _BpfAttrObj(ctypes.Structure):
    _fields_ = [
        ("pathname", ctypes.c_uint64),
        ("bpf_fd", ctypes.c_uint32),
        ("file_flags", ctypes.c_uint32),
    ]


class _BpfAttrMapElem(ctypes.Structure):
    _fields_ = [
        ("map_fd", ctypes.c_uint32),
        ("_pad", ctypes.c_uint32),
        ("key", ctypes.c_uint64),
        ("value_or_next_key", ctypes.c_uint64),
        ("flags", ctypes.c_uint64),
    ]


def _bpf(cmd, attr, size):
    ret = _libc.syscall(ctypes.c_long(__NR_bpf), ctypes.c_int(cmd),
                         ctypes.byref(attr), ctypes.c_uint(size))
    if ret < 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    return ret


def bpf_obj_get(pinned_path: str) -> int:
    """Open a pinned map/prog by its bpffs path, returning a kernel fd."""
    path_buf = ctypes.create_string_buffer(pinned_path.encode())
    attr = _BpfAttrObj()
    attr.pathname = ctypes.cast(path_buf, ctypes.c_void_p).value
    return _bpf(BPF_OBJ_GET, attr, ctypes.sizeof(attr))


def bpf_map_update_elem(map_fd: int, key: bytes, value: bytes, flags: int = BPF_ANY) -> None:
    key_buf = ctypes.create_string_buffer(bytes(key))
    val_buf = ctypes.create_string_buffer(bytes(value))
    attr = _BpfAttrMapElem()
    attr.map_fd = map_fd
    attr.key = ctypes.cast(key_buf, ctypes.c_void_p).value
    attr.value_or_next_key = ctypes.cast(val_buf, ctypes.c_void_p).value
    attr.flags = flags
    _bpf(BPF_MAP_UPDATE_ELEM, attr, ctypes.sizeof(attr))


def bpf_map_lookup_elem(map_fd: int, key: bytes, value_size: int) -> bytes:
    key_buf = ctypes.create_string_buffer(bytes(key))
    val_buf = ctypes.create_string_buffer(value_size)
    attr = _BpfAttrMapElem()
    attr.map_fd = map_fd
    attr.key = ctypes.cast(key_buf, ctypes.c_void_p).value
    attr.value_or_next_key = ctypes.cast(val_buf, ctypes.c_void_p).value
    _bpf(BPF_MAP_LOOKUP_ELEM, attr, ctypes.sizeof(attr))
    return val_buf.raw


def bpf_map_delete_elem(map_fd: int, key: bytes) -> None:
    key_buf = ctypes.create_string_buffer(bytes(key))
    attr = _BpfAttrMapElem()
    attr.map_fd = map_fd
    attr.key = ctypes.cast(key_buf, ctypes.c_void_p).value
    _bpf(BPF_MAP_DELETE_ELEM, attr, ctypes.sizeof(attr))


class PinnedMapCache:
    """Caches open fds for pinned maps by name, opened once per process
    lifetime (the agent is long-running -- this is exactly the same
    lifecycle libbpf-based agents rely on)."""

    def __init__(self, pin_base: str):
        self.pin_base = pin_base
        self._fds = {}

    def fd(self, name: str) -> int:
        if name not in self._fds:
            self._fds[name] = bpf_obj_get(f"{self.pin_base}/{name}")
        return self._fds[name]

    def update(self, name: str, key: bytes, value: bytes, flags: int = BPF_ANY) -> None:
        bpf_map_update_elem(self.fd(name), key, value, flags)

    def lookup(self, name: str, key: bytes, value_size: int) -> bytes:
        return bpf_map_lookup_elem(self.fd(name), key, value_size)

    def delete(self, name: str, key: bytes) -> None:
        bpf_map_delete_elem(self.fd(name), key)
