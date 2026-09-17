#!/usr/bin/env python3
"""
gtp5g_genl.py -- generic-netlink client for gtp5g's PDR/FAR control
interface. Rewritten from scratch (the prior copy on the test server was
zeroed by an unrelated crash mid-write -- see HANDOFF.md).

Attribute IDs taken directly from the kernel module's own headers
(include/genl.h, include/genl_pdr.h, include/genl_far.h) on the test
server, not from memory -- verified by reading them fresh in this
session:

  GTP5G_CMD_ADD_PDR=1, GTP5G_CMD_ADD_FAR=2
  GTP5G_LINK=1  (device_attrs, shared across PDR/FAR/QER/URR)
  GTP5G_PDR_ID=3, GTP5G_PDR_PRECEDENCE=4, GTP5G_PDR_PDI=5,
  GTP5G_OUTER_HEADER_REMOVAL=6, GTP5G_PDR_FAR_ID=7
  GTP5G_PDI_UE_ADDR_IPV4=1, GTP5G_PDI_F_TEID=2, GTP5G_PDI_SRC_INTF=4
  GTP5G_F_TEID_I_TEID=1, GTP5G_F_TEID_GTPU_ADDR_IPV4=2
  GTP5G_FAR_ID=3, GTP5G_FAR_APPLY_ACTION=4, GTP5G_FAR_FORWARDING_PARAMETER=5

Confirmed by reading src/genl/genl_far.c and src/genl/genl_pdr.c: the
family is registered with its .policy fields commented out, so the
kernel's generic-netlink layer does NOT auto-validate attribute
presence/type -- gtp5g_genl_add_far()/add_pdr() do their own
info->attrs[...] NULL checks before every use. GTP5G_FAR_APPLY_ACTION
is explicitly read with a nla_len()-based switch supporting both u8
and u16 encodings (far_fill(), genl_far.c line ~470). No missing-check
path was found reachable from the minimal attribute sets this script
sends. Still: run additions one at a time and check dmesg after each.
"""
import socket
import struct
import sys
import os

NETLINK_GENERIC = 16

GENL_ID_CTRL = 0x10
CTRL_CMD_GETFAMILY = 3
CTRL_ATTR_FAMILY_ID = 1
CTRL_ATTR_FAMILY_NAME = 2

NLM_F_REQUEST = 0x1
NLM_F_ACK = 0x4

NLMSG_ERROR = 2
NLMSG_DONE = 3

# gtp5g_cmd (include/genl.h)
GTP5G_CMD_ADD_PDR = 1
GTP5G_CMD_ADD_FAR = 2

# gtp5g_device_attrs (include/genl.h) -- shared "which device" attr
GTP5G_LINK = 1

# gtp5g_pdr_attrs (include/genl_pdr.h)
GTP5G_PDR_ID = 3
GTP5G_PDR_PRECEDENCE = 4
GTP5G_PDR_PDI = 5
GTP5G_OUTER_HEADER_REMOVAL = 6
GTP5G_PDR_FAR_ID = 7

# gtp5g_pdi_attrs (nested in GTP5G_PDR_PDI)
GTP5G_PDI_UE_ADDR_IPV4 = 1
GTP5G_PDI_F_TEID = 2
GTP5G_PDI_SRC_INTF = 4

# gtp5g_f_teid_attrs (nested in GTP5G_PDI_F_TEID)
GTP5G_F_TEID_I_TEID = 1
GTP5G_F_TEID_GTPU_ADDR_IPV4 = 2

# gtp5g_far_attrs (include/genl_far.h)
GTP5G_FAR_ID = 3
GTP5G_FAR_APPLY_ACTION = 4
GTP5G_FAR_FORWARDING_PARAMETER = 5

# gtp5g_forwarding_parameter_attrs (nested in GTP5G_FAR_FORWARDING_PARAMETER)
GTP5G_FORWARDING_PARAMETER_OUTER_HEADER_CREATION = 1

# gtp5g_outer_header_creation_attrs
GTP5G_OUTER_HEADER_CREATION_DESCRIPTION = 1
GTP5G_OUTER_HEADER_CREATION_O_TEID = 2
GTP5G_OUTER_HEADER_CREATION_PEER_ADDR_IPV4 = 3
GTP5G_OUTER_HEADER_CREATION_PORT = 4

FAR_ACTION_DROP = 0x01
FAR_ACTION_FORW = 0x02

GTP5G_OUTER_HEADER_CREATION_GTPU_UDP_IPV4 = 0x0100  # per 3GPP TS 29.244 OHC description bitmask


def nla(nla_type, payload=b""):
    length = 4 + len(payload)
    header = struct.pack("=HH", length, nla_type)
    padded = header + payload
    pad_len = (4 - (length % 4)) % 4
    return padded + b"\x00" * pad_len


def nla_nested(nla_type, *attrs):
    return nla(nla_type, b"".join(attrs))


def nla_u8(nla_type, value):
    return nla(nla_type, struct.pack("=B", value))


def nla_u16(nla_type, value):
    return nla(nla_type, struct.pack("=H", value))


def nla_u32(nla_type, value):
    return nla(nla_type, struct.pack("=I", value))


def nla_be32(nla_type, value):
    return nla(nla_type, struct.pack("!I", value))


class GenlSocket:
    def __init__(self):
        self.nl = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_GENERIC)
        self.nl.bind((0, 0))
        self.seq = 0
        self.family_id = None

    def _send_recv(self, msg_type, flags, payload):
        self.seq += 1
        seq = self.seq
        total_len = 16 + len(payload)
        hdr = struct.pack("=IHHII", total_len, msg_type, flags, seq, 0)
        self.nl.send(hdr + payload)
        resp = self.nl.recv(65536)
        r_len, r_type, r_flags, r_seq, r_pid = struct.unpack_from("=IHHII", resp, 0)
        return r_type, resp

    def resolve_family(self, name="gtp5g"):
        genlhdr = struct.pack("=BBH", CTRL_CMD_GETFAMILY, 1, 0)
        payload = genlhdr + nla(CTRL_ATTR_FAMILY_NAME, name.encode() + b"\x00")
        r_type, resp = self._send_recv(GENL_ID_CTRL, NLM_F_REQUEST | NLM_F_ACK, payload)
        if r_type == NLMSG_ERROR:
            (errno_val,) = struct.unpack_from("=i", resp, 16)
            raise OSError(-errno_val, f"resolve_family({name}): {os.strerror(-errno_val)}")
        # parse attrs after nlmsghdr(16) + genlmsghdr(4)
        off = 20
        end = r_len_from(resp)
        while off < end:
            a_len, a_type = struct.unpack_from("=HH", resp, off)
            if a_len < 4:
                break
            if a_type == CTRL_ATTR_FAMILY_ID:
                (fam_id,) = struct.unpack_from("=H", resp, off + 4)
                self.family_id = fam_id
            pad = (4 - (a_len % 4)) % 4
            off += a_len + pad
        if self.family_id is None:
            raise RuntimeError(f"family '{name}' not found (is gtp5g.ko loaded?)")
        return self.family_id

    def cmd(self, command, payload, ack=True):
        genlhdr = struct.pack("=BBH", command, 1, 0)
        flags = NLM_F_REQUEST | (NLM_F_ACK if ack else 0)
        r_type, resp = self._send_recv(self.family_id, flags, genlhdr + payload)
        if r_type == NLMSG_ERROR:
            (errno_val,) = struct.unpack_from("=i", resp, 16)
            if errno_val != 0:
                raise OSError(-errno_val, os.strerror(-errno_val))
        return resp

    def close(self):
        self.nl.close()


def r_len_from(resp):
    (r_len,) = struct.unpack_from("=I", resp, 0)
    return r_len


def add_far(gs, ifindex, far_id, action=FAR_ACTION_DROP, o_teid=None, peer_ipv4=None, port=2152):
    attrs = nla_u32(GTP5G_LINK, ifindex) + nla_u32(GTP5G_FAR_ID, far_id)
    attrs += nla_u16(GTP5G_FAR_APPLY_ACTION, action)
    if action == FAR_ACTION_FORW and o_teid is not None and peer_ipv4 is not None:
        ohc = nla_u16(GTP5G_OUTER_HEADER_CREATION_DESCRIPTION, GTP5G_OUTER_HEADER_CREATION_GTPU_UDP_IPV4)
        ohc += nla_u32(GTP5G_OUTER_HEADER_CREATION_O_TEID, o_teid)
        ohc += nla_be32(GTP5G_OUTER_HEADER_CREATION_PEER_ADDR_IPV4, peer_ipv4)
        ohc += nla_u16(GTP5G_OUTER_HEADER_CREATION_PORT, port)
        fwd_param = nla_nested(GTP5G_FORWARDING_PARAMETER_OUTER_HEADER_CREATION, ohc)
        attrs += nla_nested(GTP5G_FAR_FORWARDING_PARAMETER, fwd_param)
    gs.cmd(GTP5G_CMD_ADD_FAR, attrs)
    print(f"[+] FAR {far_id} added (action={action:#x})")


def add_pdr(gs, ifindex, pdr_id, precedence, far_id, ue_addr_ipv4=None, i_teid=None,
            gtpu_addr_ipv4=None, src_intf=None, outer_header_removal=None):
    attrs = nla_u32(GTP5G_LINK, ifindex)
    attrs += nla_u16(GTP5G_PDR_ID, pdr_id)
    attrs += nla_u32(GTP5G_PDR_PRECEDENCE, precedence)
    if outer_header_removal is not None:
        attrs += nla_u8(GTP5G_OUTER_HEADER_REMOVAL, outer_header_removal)
    pdi = b""
    if ue_addr_ipv4 is not None:
        pdi += nla_be32(GTP5G_PDI_UE_ADDR_IPV4, ue_addr_ipv4)
    if i_teid is not None or gtpu_addr_ipv4 is not None:
        f_teid = b""
        if i_teid is not None:
            f_teid += nla_u32(GTP5G_F_TEID_I_TEID, i_teid)
        if gtpu_addr_ipv4 is not None:
            f_teid += nla_be32(GTP5G_F_TEID_GTPU_ADDR_IPV4, gtpu_addr_ipv4)
        pdi += nla_nested(GTP5G_PDI_F_TEID, f_teid)
    if src_intf is not None:
        pdi += nla_u8(GTP5G_PDI_SRC_INTF, src_intf)
    if pdi:
        attrs += nla_nested(GTP5G_PDR_PDI, pdi)
    attrs += nla_u32(GTP5G_PDR_FAR_ID, far_id)
    gs.cmd(GTP5G_CMD_ADD_PDR, attrs)
    print(f"[+] PDR {pdr_id} added (far_id={far_id})")


if __name__ == "__main__":
    ifname = sys.argv[1] if len(sys.argv) > 1 else "gtp5gtest0"
    ifindex = socket.if_nametoindex(ifname)
    gs = GenlSocket()
    fam = gs.resolve_family("gtp5g")
    print(f"[+] gtp5g genl family id = {fam}, ifindex({ifname}) = {ifindex}")

    step = sys.argv[2] if len(sys.argv) > 2 else "far_drop"
    if step == "far_drop":
        add_far(gs, ifindex, far_id=1, action=FAR_ACTION_DROP)
    elif step == "far_forw":
        add_far(gs, ifindex, far_id=2, action=FAR_ACTION_FORW,
                 o_teid=0x1000, peer_ipv4=struct.unpack("!I", socket.inet_aton("10.0.0.2"))[0])
    elif step == "pdr":
        add_pdr(gs, ifindex, pdr_id=1, precedence=100, far_id=1, outer_header_removal=0)
    else:
        print(f"unknown step '{step}'")
    gs.close()
