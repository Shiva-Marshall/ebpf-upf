#!/usr/bin/env python3
"""
native_throughput.py -- native-XDP throughput measurement (Phase 8),
replacing Table 9's analytical projection with a real number.

Ground truth is the RECEIVING NIC's own hardware rx_packets/rx_bytes
counter (ethtool -S), not the generator's self-reported "sent" count: a
first run showed the generator claiming 6.15M packets sent while the
receiving NIC's hardware counter recorded only 2.18M actually arriving
(the AF_PACKET generator's TX ring silently drops under its own
back-pressure once PACKET_QDISC_BYPASS removes the qdisc's queueing --
sendmmsg() does not surface this as an error). Every number this script
reports is therefore derived from ethtool -S deltas on the RX side, cross-
checked against the XDP programme's own /metrics rx_total counter (a
second, independent count of the same event, at a different layer).

CPU utilization is sampled via mpstat -P ALL over the run duration; the
report keeps utilization only for cores this NIC's RX queues are IRQ-
affined to, aggregated as a single mean, since idle unrelated cores
would understate the true per-core cost.
"""
import argparse
import re
import subprocess
import sys
import time


def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout


def ethtool_counters(iface):
    out = sh(f"ethtool -S {iface}")
    d = {}
    for line in out.splitlines():
        line = line.strip()
        if ":" not in line:
            continue
        k, _, v = line.partition(":")
        v = v.strip()
        if v.isdigit():
            d[k.strip()] = int(v)
    return d


def metrics_counter(stage):
    out = sh("curl -s http://127.0.0.1:9090/metrics")
    m = re.search(rf'upf_packets_total\{{stage="{stage}"\}}\s+(\d+)', out)
    return int(m.group(1)) if m else 0


def irq_snapshot(iface):
    """Per-CPU interrupt counts for this iface's TxRx IRQ lines, as a list of
    lists (one row per IRQ line, one column per CPU) -- read directly, not
    via a shell pipeline, so the row/column shape is unambiguous."""
    rows = []
    with open("/proc/interrupts") as f:
        for line in f:
            if f"i40e-{iface}-TxRx" not in line:
                continue
            parts = line.split()
            # After the leading "NN:" field, one integer column per CPU,
            # until the first non-numeric field (the IR-PCI-MSI... label).
            counts = []
            for tok in parts[1:]:
                if tok.isdigit():
                    counts.append(int(tok))
                else:
                    break
            rows.append(counts)
    return rows


def irq_active_cpus(before, after):
    """CPU indices whose interrupt count increased on any of this iface's
    IRQ lines between two irq_snapshot() calls -- the CPUs that actually
    handled this run's RX/TX for this NIC, not a guessed range."""
    active = set()
    for row_b, row_a in zip(before, after):
        for cpu, (b, a) in enumerate(zip(row_b, row_a)):
            if a > b:
                active.add(cpu)
    return sorted(active)


def mpstat_sample(duration_s, cpu_list):
    cpus = ",".join(str(c) for c in cpu_list)
    out = sh(f"mpstat -P {cpus} 1 {duration_s} | tail -n {len(cpu_list)}")
    idles = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 3 or parts[2] == "CPU":
            continue
        try:
            idle = float(parts[-1])
            idles.append(idle)
        except ValueError:
            continue
    if not idles:
        return None
    mean_idle = sum(idles) / len(idles)
    return 100.0 - mean_idle


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--gen-iface", default="enp24s0f1")
    ap.add_argument("--rx-iface", default="enp24s0f0")
    ap.add_argument("--nthreads", type=int, required=True)
    ap.add_argument("--duration", type=int, default=5)
    ap.add_argument("--frame-bytes", type=int, default=64)
    ap.add_argument("--teid-base", default="0x9000")
    args = ap.parse_args()

    before_eth = ethtool_counters(args.rx_iface)
    before_metric = metrics_counter("rx_total")
    irq_before = irq_snapshot(args.rx_iface)

    blast = f"./test/xdp_throughput_blast {args.gen_iface} {args.nthreads} {args.duration} {args.teid_base} {args.frame_bytes}"
    # mpstat samples ALL CPUs for the run duration; which columns matter is
    # decided afterward from the IRQ delta, not guessed beforehand.
    import threading
    mpstat_raw = {}

    def do_mpstat():
        mpstat_raw["out"] = sh(f"mpstat -P ALL 1 {args.duration}")

    t = threading.Thread(target=do_mpstat)
    t.start()
    blast_out = sh(f"sudo {blast}")
    t.join()

    time.sleep(1)  # let final RX settle
    after_eth = ethtool_counters(args.rx_iface)
    after_metric = metrics_counter("rx_total")
    irq_after = irq_snapshot(args.rx_iface)
    active_cpus = irq_active_cpus(irq_before, irq_after)

    util = None
    if active_cpus and mpstat_raw.get("out"):
        idles = []
        for line in mpstat_raw["out"].splitlines():
            parts = line.split()
            if len(parts) < 3 or not parts[2].isdigit():
                continue
            cpu = int(parts[2])
            if cpu not in active_cpus:
                continue
            try:
                idles.append(float(parts[-1]))
            except ValueError:
                pass
        if idles:
            util = 100.0 - (sum(idles) / len(idles))
    mpstat_result = {"util": util}

    rx_pkts = after_eth.get("rx_packets", 0) - before_eth.get("rx_packets", 0)
    rx_bytes = after_eth.get("rx_bytes", 0) - before_eth.get("rx_bytes", 0)
    metric_delta = after_metric - before_metric

    m = re.search(r"blast_sent=(\d+)", blast_out)
    sent = int(m.group(1)) if m else 0

    achieved_mpps = rx_pkts / args.duration / 1e6
    achieved_gbps = rx_bytes * 8 / args.duration / 1e9
    loss_vs_sent = max(0.0, (sent - rx_pkts) / sent) if sent else float("nan")
    xdp_metric_matches_hw = (metric_delta == rx_pkts)

    print(f"nthreads={args.nthreads} frame_bytes={args.frame_bytes} duration_s={args.duration} "
          f"sent={sent} rx_hw_pkts={rx_pkts} xdp_metric_delta={metric_delta} "
          f"hw_matches_xdp_metric={xdp_metric_matches_hw} "
          f"achieved_mpps={achieved_mpps:.4f} achieved_gbps={achieved_gbps:.4f} "
          f"loss_vs_sent={loss_vs_sent:.4f} "
          f"active_cpus={len(active_cpus)} cpu_util_pct={mpstat_result.get('util')}")


if __name__ == "__main__":
    main()
