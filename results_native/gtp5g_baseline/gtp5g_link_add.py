#!/usr/bin/env python3
"""
gtp5g_link_add.py -- create a gtp5g netdevice via raw rtnetlink, since
gtp5g requires passing a bound UDP socket fd (IFLA_GTP5G_FD1) at link
creation time, which plain `ip link add` cannot do and which pyroute2
does not have a registered plugin for (confirmed: kind="gtp5g" alone
sends a message the kernel accepts as a genuine gtp5g creation attempt,
but rejects with EINVAL for the missing mandatory FD1 attribute).

Written from first principles against the kernel module's own attribute
enum (include/link.h): IFLA_GTP5G_FD1=1, IFLA_GTP5G_PDR_HASHSIZE=2,
IFLA_GTP5G_ROLE=3. Default role is GTP5G_ROLE_UPF (0), which is what we
want (testing gtp5g's own data-plane forwarding).
"""
import socket
import struct
import sys
import os

RTM_NEWLINK = 16
NLM_F_REQUEST = 0x1
NLM_F_ACK = 0x4
NLM_F_CREATE = 0x400
NLM_F_EXCL = 0x200

IFLA_IFNAME = 3
IFLA_LINKINFO = 18
IFLA_INFO_KIND = 1
IFLA_INFO_DATA = 2

IFLA_GTP5G_FD1 = 1
IFLA_GTP5G_PDR_HASHSIZE = 2
IFLA_GTP5G_ROLE = 3

NETLINK_ROUTE = 0


def nla(nla_type, payload):
    """One netlink attribute, header + payload, padded to 4 bytes."""
    length = 4 + len(payload)
    header = struct.pack("=HH", length, nla_type)
    padded = header + payload
    pad_len = (4 - (length % 4)) % 4
    return padded + b"\x00" * pad_len


def nla_nested(nla_type, *attrs):
    payload = b"".join(attrs)
    return nla(nla_type, payload)


def nla_u32(nla_type, value):
    return nla(nla_type, struct.pack("=I", value))


def nla_str(nla_type, value):
    return nla(nla_type, value.encode() + b"\x00")


def create_gtp5g_link(ifname, gtpu_port=2152, pdr_hashsize=128):
    # 1. Bind a UDP socket to the GTP-U port; its fd becomes the kernel's
    #    encapsulation socket for this gtp5g device.
    sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sk.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sk.bind(("0.0.0.0", gtpu_port))
    fd1 = sk.fileno()

    # 2. Build IFLA_INFO_DATA (gtp5g-specific attributes).
    info_data = nla_nested(
        IFLA_INFO_DATA,
        nla_u32(IFLA_GTP5G_FD1, fd1),
        nla_u32(IFLA_GTP5G_PDR_HASHSIZE, pdr_hashsize),
    )
    link_info = nla_nested(
        IFLA_LINKINFO,
        nla_str(IFLA_INFO_KIND, "gtp5g"),
        info_data,
    )
    ifname_attr = nla_str(IFLA_IFNAME, ifname)

    ifinfomsg = struct.pack("=BBHiII", 0, 0, 0, 0, 0, 0)  # family,pad,type,index,flags,change
    payload = ifinfomsg + ifname_attr + link_info

    seq = os.getpid() & 0xffff
    nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL
    total_len = 16 + len(payload)
    nlmsghdr = struct.pack("=IHHII", total_len, RTM_NEWLINK, nlmsg_flags, seq, 0)
    msg = nlmsghdr + payload

    nl = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_ROUTE)
    nl.bind((0, 0))
    nl.send(msg)
    resp = nl.recv(65536)

    # Parse the ack: nlmsghdr, then if type==NLMSG_ERROR(2), a 4-byte errno.
    r_len, r_type, r_flags, r_seq, r_pid = struct.unpack_from("=IHHII", resp, 0)
    if r_type == 2:  # NLMSG_ERROR
        (errno_val,) = struct.unpack_from("=i", resp, 16)
        if errno_val != 0:
            raise OSError(-errno_val, os.strerror(-errno_val))
        print(f"[+] gtp5g link '{ifname}' created OK (fd1={fd1}, bound to :{gtpu_port})")
    else:
        print(f"[?] unexpected netlink response type={r_type}")
    nl.close()
    return sk  # caller may keep this open, though the kernel holds its own ref


if __name__ == "__main__":
    name = sys.argv[1] if len(sys.argv) > 1 else "gtp5gtest0"
    create_gtp5g_link(name)
