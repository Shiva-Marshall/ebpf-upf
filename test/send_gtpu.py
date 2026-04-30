#!/usr/bin/env python3
"""
Inject GTP-U test traffic toward the host veth (where the XDP program is
attached). Runs *inside* the upfns netns so packets actually traverse the
host-side veth and hit XDP.

Usage:  sudo ip netns exec upfns python3 send_gtpu.py [--n N] [--teid T] [--mix]
"""
import argparse
import os
import sys
import time

from scapy.all import Ether, IP, UDP, Raw, sendp, conf
from scapy.contrib.gtp import GTP_U_Header, GTPPDUSessionContainer

# Inside the netns we use the namespace-side veth.
DEFAULT_IFACE = "upf_ns"
DST_MAC = None  # learned via ARP; we'll force a static dst MAC below


def build_gpdu(teid: int, payload_size: int = 64) -> bytes:
    """A valid uplink G-PDU: Ether/IP/UDP(2152)/GTP-U(G-PDU)/inner-IP/payload."""
    inner = IP(src="10.45.0.1", dst="8.8.8.8") / UDP(sport=12345, dport=53) / \
            Raw(load=b"X" * payload_size)
    gtp = GTP_U_Header(teid=teid, gtp_type=0xff)  # 0xff = G-PDU
    return bytes(Ether(dst="ff:ff:ff:ff:ff:ff") /
                 IP(src="10.99.0.2", dst="10.99.0.1") /
                 UDP(sport=2152, dport=2152) /
                 gtp / inner)


def build_ctrl_msg(teid: int) -> bytes:
    """A GTP-U control message (Echo Request, type 0x01) — should XDP_PASS."""
    gtp = GTP_U_Header(teid=teid, gtp_type=0x01)
    return bytes(Ether(dst="ff:ff:ff:ff:ff:ff") /
                 IP(src="10.99.0.2", dst="10.99.0.1") /
                 UDP(sport=2152, dport=2152) / gtp / Raw(load=b""))


def build_non_gtp() -> bytes:
    """Plain UDP, not on port 2152 — should XDP_PASS as non-GTP."""
    return bytes(Ether(dst="ff:ff:ff:ff:ff:ff") /
                 IP(src="10.99.0.2", dst="10.99.0.1") /
                 UDP(sport=12345, dport=80) / Raw(load=b"hello"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", default=DEFAULT_IFACE)
    ap.add_argument("--n", type=int, default=100, help="packets to send")
    ap.add_argument("--teid", type=lambda x: int(x, 0), default=0x1000,
                    help="TEID to use (hex or decimal); 0x1000 matches "
                         "agent.py bootstrap")
    ap.add_argument("--mix", action="store_true",
                    help="send a mix: known-TEID, unknown-TEID, control, "
                         "non-GTP")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    conf.iface = args.iface
    conf.verb = 0

    if args.mix:
        # 4 categories so each metric counter advances visibly
        plan = [
            ("known TEID  (G-PDU, hit)",       build_gpdu(args.teid),  args.n // 4),
            ("unknown TEID (G-PDU, miss)",     build_gpdu(0xDEADBEEF), args.n // 4),
            ("GTP-U control (echo)",           build_ctrl_msg(args.teid), args.n // 4),
            ("non-GTP UDP",                    build_non_gtp(),        args.n // 4),
        ]
    else:
        plan = [(f"G-PDU teid=0x{args.teid:08x}", build_gpdu(args.teid), args.n)]

    total = 0
    t0 = time.monotonic()
    for label, pkt, count in plan:
        if not args.quiet:
            print(f"  -> sending {count} x {label}")
        sendp(pkt, iface=args.iface, count=count, verbose=False)
        total += count
    dt = time.monotonic() - t0
    print(f"[+] sent {total} packets in {dt*1000:.1f} ms "
          f"({total/dt:.0f} pps via Python sendp)")


if __name__ == "__main__":
    if os.geteuid() != 0:
        sys.exit("must run as root (raw socket)")
    main()
