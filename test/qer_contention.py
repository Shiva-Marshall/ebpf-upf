#!/usr/bin/env python3
"""
qer_contention.py -- QER token-bucket contention experiment (Reviewer 2
point 4; Reviewer 1's observation that shared-QER state creates lock
contention while per-CPU buckets can temporarily violate the configured
rate).

Installs <nflows> sessions, each with its own TEID, all pointing at a
single shared QER, then drives them with qer_blast (which varies the
outer UDP source port so RSS spreads the flows across receive CPUs).

Two quantities are recorded per run:

  * admitted/rejected packet counts, from which the achieved admitted
    rate is compared against the QER's configured MBR. The per-CPU
    build is expected to overshoot roughly in proportion to the number
    of CPUs engaged, since each refills its own bucket against the same
    MBR; the shared spin-locked build is expected to track the MBR.

  * the number of distinct CPUs that actually executed the QER path,
    counted from the per-CPU `metrics` map. This is the multiplier the
    overshoot should be compared against -- it is measured, not assumed,
    because RSS spreading depends on the hash landing flows on distinct
    queues and cannot be taken on faith.

Run as root, on the server, with the datapath already loaded:
  sudo python3 test/qer_contention.py --nflows 8 --pps 200000 \
       --duration 10 --mbr-bps 50000000 --burst 65536 --label percpu
"""
import argparse
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "loader"))
import agent  # noqa: E402

QER_PASS_IDX = agent.METRIC_NAMES.index("tc_qer_pass")
QER_DROP_IDX = agent.METRIC_NAMES.index("tc_qer_drop")

TEID_BASE = 0x7000
PDR_BASE = 0x7000


def percpu_metric(dump, idx):
    """Return the list of per-CPU values for metric index `idx`."""
    for entry in dump:
        key = entry.get("key")
        if isinstance(key, list):
            k = int.from_bytes(bytes(int(x, 16) for x in key), "little")
        else:
            k = int(key)
        if k != idx:
            continue
        vals = []
        for v in entry.get("values", []):
            val = v.get("value")
            if isinstance(val, list):
                vals.append(int.from_bytes(bytes(int(x, 16) for x in val), "little"))
            else:
                vals.append(int(val))
        return vals
    return []


TC_PROG_PIN = "/sys/fs/bpf/upf/tc_prog/classifier"


def prog_stats():
    """(run_time_ns, run_cnt) for the TC ingress programme.

    Requires kernel.bpf_stats_enabled=1. The accounting overhead this adds
    applies identically to both build variants, so the comparison between
    them stays valid even though the absolute figures carry that overhead.
    """
    import json
    out = subprocess.run(["bpftool", "-j", "prog", "show", "pinned", TC_PROG_PIN],
                         capture_output=True, text=True)
    try:
        j = json.loads(out.stdout)
    except Exception:
        return 0, 0
    if isinstance(j, list):
        j = j[0]
    return j.get("run_time_ns", 0), j.get("run_cnt", 0)


def snapshot():
    d = agent.map_dump("metrics")
    urr = agent.read_urr(1) or {"bytes_ul": 0, "pkts_ul": 0}
    rt, rc = prog_stats()
    return (percpu_metric(d, QER_PASS_IDX),
            percpu_metric(d, QER_DROP_IDX),
            urr["bytes_ul"], rt, rc)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--nflows", type=int, required=True)
    ap.add_argument("--pps", type=int, default=200000)
    ap.add_argument("--duration", type=int, default=10)
    ap.add_argument("--mbr-bps", type=int, required=True)
    ap.add_argument("--burst", type=int, default=65536)
    ap.add_argument("--label", required=True, help="percpu | shared")
    ap.add_argument("--iface", default="enp24s0f1")
    ap.add_argument("--netns", default="upf_hw_test")
    ap.add_argument("--out-ifindex", type=int, default=2)
    args = ap.parse_args()

    # Rule state: one FAR, one shared QER, nflows sessions all referencing it.
    agent.install_far(1, agent.FAR_FORWARD, out_ifindex=args.out_ifindex)
    agent.install_qer(1, mbr_ul_bps=args.mbr_bps, burst_bytes=args.burst)
    for i in range(args.nflows):
        agent.install_session(TEID_BASE + i, PDR_BASE + i, qer_id=1, far_id=1)

    time.sleep(0.5)
    pass_before, drop_before, urr_before, rt_before, rc_before = snapshot()

    blast = os.path.join(os.path.dirname(os.path.abspath(__file__)), "qer_blast")
    cmd = ["ip", "netns", "exec", args.netns, blast,
           args.iface, str(args.pps), str(args.duration),
           hex(TEID_BASE), str(args.nflows)]
    out = subprocess.run(cmd, capture_output=True, text=True)
    blast_line = out.stdout.strip()

    time.sleep(0.5)
    pass_after, drop_after, urr_after, rt_after, rc_after = snapshot()

    n = min(len(pass_before), len(pass_after))
    per_cpu_pass = [pass_after[i] - pass_before[i] for i in range(n)]
    m = min(len(drop_before), len(drop_after))
    per_cpu_drop = [drop_after[i] - drop_before[i] for i in range(m)]

    admitted = sum(per_cpu_pass)
    rejected = sum(per_cpu_drop)
    cpus_engaged = sum(1 for i in range(n)
                       if per_cpu_pass[i] > 0 or (i < m and per_cpu_drop[i] > 0))

    # Admitted bytes are taken from the URR counters rather than assumed
    # from a nominal packet size: upf_urr_update() is called with exactly
    # the same pkt_len the token bucket meters, and only for admitted
    # packets, so this is the metered quantity itself rather than a
    # reconstruction of it.
    admitted_bytes = urr_after - urr_before
    metered_pkt_bytes = (admitted_bytes / admitted) if admitted else 0
    admitted_bps = (admitted_bytes * 8) / args.duration
    overshoot = admitted_bps / args.mbr_bps if args.mbr_bps else float("nan")

    d_rt = rt_after - rt_before
    d_rc = rc_after - rc_before
    ns_per_run = (d_rt / d_rc) if d_rc else 0.0

    for cleanup_i in range(args.nflows):
        agent.remove_session(TEID_BASE + cleanup_i, PDR_BASE + cleanup_i)

    print(f"label={args.label} nflows={args.nflows} pps={args.pps} "
          f"dur={args.duration} mbr_bps={args.mbr_bps} burst={args.burst} "
          f"admitted={admitted} rejected={rejected} cpus_engaged={cpus_engaged} "
          f"metered_pkt_bytes={metered_pkt_bytes:.1f} "
          f"admitted_bps={admitted_bps:.0f} overshoot={overshoot:.2f} "
          f"ns_per_run={ns_per_run:.1f} prog_runs={d_rc} {blast_line}")


if __name__ == "__main__":
    main()
