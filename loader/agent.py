#!/usr/bin/env python3
"""
Minimal PFCP-stub control-plane agent for the eBPF UPF prototype.

This stands in for the Go-based PFCP agent described in the paper. It:
  - populates the BPF maps with synthetic PDR/QER/FAR + TEID->session entries
  - exposes a Prometheus-compatible /metrics endpoint
  - exposes a /ruleupdate endpoint that performs a batch update and reports
    wall-clock latency (used by the rule-update measurement)

Maps are accessed via bpftool, which talks to the kernel via the bpf() syscall.
This is wire-equivalent to what cilium/ebpf or libbpf would do, just in Python.
"""
import argparse
import json
import os
import struct
import subprocess
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread

import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from bpf_syscall import PinnedMapCache

BPFTOOL = f"/usr/lib/linux-tools/{os.uname().release}/bpftool"
PIN_BASE = "/sys/fs/bpf/upf"

# Hot-path map writes (install_session, modify_tc_bundle, etc.) go through
# a direct bpf() syscall via ctypes -- see loader/bpf_syscall.py for why:
# the original subprocess-spawned `sudo bpftool` approach cost ~11-15ms per
# call, purely from sudo/exec overhead, found while benchmarking against
# eUPF's REST API on the same hardware (Section: same-testbed eUPF
# comparison). Bulk reads for /metrics (map_dump, not on the rule-install
# hot path) continue to use bpftool for convenience.
_maps = PinnedMapCache(PIN_BASE)

METRIC_NAMES = [
    "rx_total", "rx_gtpu", "rx_gpdu",
    "hit", "miss_teid", "miss_pdr",
    "pass_nongtp", "pass_ctrl", "drop_parse",
    "tc_miss_far", "tc_far_drop", "tc_far_forward", "tc_far_buffer",
    "tc_decap_err", "tc_redirect_err", "tc_qer_pass", "tc_qer_drop",
    "tc_urr_updated", "tc_dl_hit", "tc_dl_miss", "tc_dl_encap_err",
]

# enum far_action in bpf/upf_maps.h
FAR_DROP, FAR_FORWARD, FAR_BUFFER = 0, 1, 2


def run(cmd, check=True):
    return subprocess.run(cmd, check=check, capture_output=True, text=True)


# ---------------- low-level map ops via bpftool ----------------

def _bytes_to_hexargs(b):
    return [f"0x{x:02x}" for x in b]


def map_update(name, key_bytes, val_bytes):
    _maps.update(name, key_bytes, val_bytes)


def map_delete(name, key_bytes):
    try:
        _maps.delete(name, key_bytes)
    except OSError:
        pass  # matches the old bpftool `check=False` behaviour: deleting an
              # already-absent key is not an error for our callers


def map_dump(name):
    cmd = ["sudo", BPFTOOL, "-j", "map", "dump", "pinned", f"{PIN_BASE}/{name}"]
    out = run(cmd).stdout
    return json.loads(out)


# ---------------- domain encoders ----------------

def enc_session(pdr_id, qer_id, far_id):
    # struct session_val { __u32 pdr_id; __u32 qer_id; __u32 far_id; __u32 _pad; }
    return struct.pack("<IIII", pdr_id, qer_id, far_id, 0)


def enc_pdr(far_id, qer_id, precedence, urr_id=1):
    # struct pdr_val { __u32 far_id; __u32 qer_id; __u32 precedence; __u32 urr_id; }
    return struct.pack("<IIII", far_id, qer_id, precedence, urr_id)


def enc_far(action, out_ifindex, peer_ipv4_be=0, out_teid_be=0):
    # struct far_val { __u32 action; __u32 out_ifindex; __u32 peer_ipv4_be; __u32 out_teid_be; }
    return struct.pack("<IIII", action, out_ifindex, peer_ipv4_be, out_teid_be)


def enc_qer(mbr_ul_bps, mbr_dl_bps, burst_bytes):
    # struct qer_val { __u64 mbr_ul_bps; __u64 mbr_dl_bps; __u32 burst_bytes; __u32 _pad; }
    return struct.pack("<QQII", mbr_ul_bps, mbr_dl_bps, burst_bytes, 0)


def enc_u32(v):
    return struct.pack("<I", v)


def install_far(far_id, action, out_ifindex=0, peer_ipv4_be=0, out_teid_be=0):
    map_update("far_table", enc_u32(far_id),
               enc_far(action, out_ifindex, peer_ipv4_be, out_teid_be))


def install_qer(qer_id, mbr_ul_bps=0, mbr_dl_bps=0, burst_bytes=0):
    """mbr_ul_bps=0 means unlimited (upf_qer_admit() fails open on mbr==0)."""
    map_update("qer_table", enc_u32(qer_id), enc_qer(mbr_ul_bps, mbr_dl_bps, burst_bytes))


def ip_to_be32_bytes(dotted):
    import socket
    return socket.inet_aton(dotted)   # already network byte order, 4 bytes


def install_dl_ue(ue_ip_dotted, teid, gnb_ip_dotted, qfi=1):
    """dl_ue_map key = UE IPv4 (network byte order); value = dl_ue_val."""
    key = ip_to_be32_bytes(ue_ip_dotted)
    teid_be = struct.pack(">I", teid)               # GTP-U TEID is stored network-order in dl_ue_val
    gnb_be  = ip_to_be32_bytes(gnb_ip_dotted)
    # struct dl_ue_val { __u32 teid_be; __u32 gnb_ipv4_be; __u16 qfi; __u16 _pad; }
    val = teid_be + gnb_be + struct.pack("<HH", qfi, 0)
    map_update("dl_ue_map", key, val)


def install_upf_config(n3_addr_dotted):
    # struct upf_config { __u32 n3_addr_be; }
    map_update("upf_config_map", enc_u32(0), ip_to_be32_bytes(n3_addr_dotted))


def read_urr(urr_id):
    """Aggregate a urr_counters entry across CPUs. Returns dict or None if absent."""
    raw = map_dump("urr_counters")
    for entry in raw:
        key = struct.unpack("<I", bytes(int(b, 0) for b in entry["key"]))[0]
        if key != urr_id:
            continue
        bytes_ul = pkts_ul = 0
        for v in entry.get("values", []):
            b = bytes(int(x, 0) for x in v["value"])
            bul, bdl, pul, pdl = struct.unpack("<QQQQ", b)
            bytes_ul += bul
            pkts_ul += pul
        return {"bytes_ul": bytes_ul, "pkts_ul": pkts_ul}
    return None


def enc_bundle_slot(far_id, qer_id, urr_id, precedence, generation):
    # struct tc_bundle_slot { u32 far_id; u32 qer_id; u32 urr_id; u32 precedence; u32 generation; u32 _pad; }
    return struct.pack("<IIIIII", far_id, qer_id, urr_id, precedence, generation, 0)


def enc_bundle(active, slot0_bytes, slot1_bytes):
    # struct tc_bundle { u32 active; u32 _pad; struct tc_bundle_slot slot[2]; }
    return struct.pack("<II", active, 0) + slot0_bytes + slot1_bytes


def install_tc_bundle(pdr_id, far_id, qer_id, urr_id, precedence, generation=0):
    """Initial install: both slots identical, active=slot 0."""
    slot = enc_bundle_slot(far_id, qer_id, urr_id, precedence, generation)
    map_update("tc_bundle_map", enc_u32(pdr_id), enc_bundle(0, slot, slot))


def modify_tc_bundle(pdr_id, far_id=None, qer_id=None, urr_id=None, precedence=None):
    """Transactional-consistency mechanism (Section on transactional
    consistency): atomically commit a change to one or more of
    far_id/qer_id/urr_id/precedence for a PDR, as a single logical unit,
    via the two-write double-buffer protocol.

    Step 1 writes the complete new tuple into the *inactive* slot -- this
    is invisible to the datapath, since `active` still names the other
    slot, so it cannot be observed mid-write by any packet.
    Step 2 flips only `active`. This is the single atomic commit point:
    every packet processed before it sees the pre-modification tuple in
    full; every packet processed after sees the post-modification tuple
    in full. No packet can ever observe a hybrid of old and new fields,
    regardless of how many of far_id/qer_id/urr_id/precedence changed
    together in this call.

    Returns the new generation number, for the caller to correlate against
    what a concurrent-traffic test observes.
    """
    # struct tc_bundle { u32 active; u32 _pad; struct tc_bundle_slot slot[2]; }
    # struct tc_bundle_slot { u32 far_id,qer_id,urr_id,precedence,generation,_pad; }
    raw = _maps.lookup("tc_bundle_map", enc_u32(pdr_id), 4 + 4 + 24 + 24)
    active, _pad = struct.unpack_from("<II", raw, 0)
    active &= 1
    slot_off = 8 + active * 24
    cur_far_id, cur_qer_id, cur_urr_id, cur_prec, cur_gen, _ = \
        struct.unpack_from("<IIIIII", raw, slot_off)
    inactive = 1 - active

    new_far_id = far_id if far_id is not None else cur_far_id
    new_qer_id = qer_id if qer_id is not None else cur_qer_id
    new_urr_id = urr_id if urr_id is not None else cur_urr_id
    new_prec   = precedence if precedence is not None else cur_prec
    new_gen    = cur_gen + 1

    cur_slot_bytes = enc_bundle_slot(cur_far_id, cur_qer_id, cur_urr_id, cur_prec, cur_gen)
    new_slot_bytes = enc_bundle_slot(new_far_id, new_qer_id, new_urr_id, new_prec, new_gen)

    slots_prep = [None, None]
    slots_prep[active] = cur_slot_bytes
    slots_prep[inactive] = new_slot_bytes
    # Step 1: new tuple in the inactive slot; active unchanged.
    map_update("tc_bundle_map", enc_u32(pdr_id), enc_bundle(active, slots_prep[0], slots_prep[1]))
    # Step 2: commit -- flip active. Single atomic visibility point.
    map_update("tc_bundle_map", enc_u32(pdr_id), enc_bundle(inactive, slots_prep[0], slots_prep[1]))

    return new_gen


def install_session(teid, pdr_id, qer_id=1, far_id=1, precedence=100, urr_id=1):
    """Install one PFCP-equivalent session: pdr_table (used by the XDP
    classification stage for PDR-existence checks), tc_bundle_map (used by
    TC ingress for the FAR/QER/URR decision -- see modify_tc_bundle for the
    transactional-consistency mechanism that protects later changes to
    this), then teid_session last."""
    map_update("pdr_table",   enc_u32(pdr_id),   enc_pdr(far_id, qer_id, precedence, urr_id))
    install_tc_bundle(pdr_id, far_id, qer_id, urr_id, precedence)
    map_update("teid_session", enc_u32(teid),    enc_session(pdr_id, qer_id, far_id))


def remove_session(teid, pdr_id):
    map_delete("teid_session",   enc_u32(teid))
    map_delete("pdr_table",      enc_u32(pdr_id))
    map_delete("tc_bundle_map",  enc_u32(pdr_id))


# ---------------- metrics ----------------

def read_metrics():
    """Return dict[name] = aggregated_count (sum over CPUs)."""
    raw = map_dump("metrics")
    out = {}
    for entry in raw:
        # Each entry: { "key": [...], "values": [{"cpu": N, "value": [...]}, ...] }
        idx = struct.unpack("<I", bytes(int(b, 0) for b in entry["key"]))[0]
        if idx >= len(METRIC_NAMES):
            continue
        total = 0
        for v in entry.get("values", []):
            total += struct.unpack("<Q", bytes(int(b, 0) for b in v["value"]))[0]
        out[METRIC_NAMES[idx]] = total
    return out


def prometheus_text():
    m = read_metrics()
    lines = ["# HELP upf_packets_total UPF packet counters by stage",
             "# TYPE upf_packets_total counter"]
    for name in METRIC_NAMES:
        lines.append(f'upf_packets_total{{stage="{name}"}} {m.get(name, 0)}')
    return "\n".join(lines) + "\n"


# ---------------- rule update timing ----------------

def measure_rule_update(n_rules):
    """
    Install n_rules sessions back-to-back, return (total_ms, per_rule_us list).
    Each session = 1 pdr_table insert + 1 teid_session insert (i.e. 2 map ops).
    """
    samples_us = []
    base_teid = 0x10000
    base_pdr  = 0x20000

    t_start = time.monotonic_ns()
    for i in range(n_rules):
        s = time.monotonic_ns()
        install_session(teid=base_teid + i, pdr_id=base_pdr + i)
        e = time.monotonic_ns()
        samples_us.append((e - s) / 1000.0)
    t_end = time.monotonic_ns()

    # Cleanup
    for i in range(n_rules):
        remove_session(base_teid + i, base_pdr + i)

    return ((t_end - t_start) / 1e6, samples_us)


# ---------------- HTTP server ----------------

class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="text/plain; charset=utf-8"):
        b = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def log_message(self, fmt, *args):
        pass  # silence default logging

    def do_GET(self):
        if self.path == "/metrics":
            self._send(200, prometheus_text())
        elif self.path.startswith("/ruleupdate"):
            # /ruleupdate?n=100
            from urllib.parse import urlparse, parse_qs
            q = parse_qs(urlparse(self.path).query)
            n = int(q.get("n", ["100"])[0])
            total_ms, per_us = measure_rule_update(n)
            body = {
                "n_rules": n,
                "total_ms": round(total_ms, 3),
                "per_rule_us_p50": sorted(per_us)[len(per_us)//2],
                "per_rule_us_p95": sorted(per_us)[int(len(per_us)*0.95)],
                "per_rule_us_p99": sorted(per_us)[int(len(per_us)*0.99)],
                "per_rule_us_min": min(per_us),
                "per_rule_us_max": max(per_us),
            }
            self._send(200, json.dumps(body, indent=2), "application/json")
        elif self.path == "/healthz":
            self._send(200, "ok\n")
        else:
            self._send(404, "not found\n")


def serve(addr, port):
    print(f"[+] agent listening on http://{addr}:{port}", flush=True)
    HTTPServer((addr, port), Handler).serve_forever()


# ---------------- bootstrap ----------------

def bootstrap_initial(n=10, out_ifindex=2):
    """Install a default FAR (id 1, FORWARD out `out_ifindex`), a default QER
    (id 1, unlimited -- mbr_ul_bps=0), and n synthetic active sessions
    referencing them, before serving. `out_ifindex` defaults to 2, matching
    enp24s0f0 on the native-XDP testbed's self-loop configuration."""
    install_far(1, FAR_FORWARD, out_ifindex=out_ifindex)
    install_qer(1, mbr_ul_bps=0, mbr_dl_bps=0, burst_bytes=0)
    print(f"[+] bootstrapping {n} initial sessions ...", flush=True)
    for i in range(n):
        install_session(teid=0x1000 + i, pdr_id=0x2000 + i)
    print(f"[+] {n} sessions installed", flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--addr", default="127.0.0.1")
    ap.add_argument("--port", default=9090, type=int)
    ap.add_argument("--initial", default=10, type=int,
                    help="number of synthetic sessions to install at startup")
    ap.add_argument("--out-ifindex", default=2, type=int,
                    help="egress ifindex for the default FAR (id 1)")
    args = ap.parse_args()

    bootstrap_initial(args.initial, out_ifindex=args.out_ifindex)
    serve(args.addr, args.port)


if __name__ == "__main__":
    main()
