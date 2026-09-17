#!/usr/bin/env python3
"""
analyze_latency.py -- parse a `bpftool map event_pipe` capture of
latency_event records (Phase 8, in-pipeline TC-ingress latency) and report
percentiles. Same capture format as the Phase 4 transactional-consistency
decision_event analysis (results_native/transactional_consistency/analyze.py):
each event prints as a "==...==" header line followed by two lines of hex
bytes.

struct latency_event { __u64 latency_ns; __u32 pkt_len; __u32 _pad; };  (16B)
"""
import sys


def parse(path):
    events = []
    with open(path) as f:
        lines = f.readlines()
    i = 0
    while i < len(lines):
        if lines[i].startswith('=='):
            hex1 = lines[i + 1].strip().replace(' ', '')
            hex2 = lines[i + 2].strip().replace(' ', '') if i + 2 < len(lines) else ''
            raw = bytes.fromhex(hex1 + hex2)[:16]
            latency_ns = int.from_bytes(raw[0:8], 'little')
            pkt_len = int.from_bytes(raw[8:12], 'little')
            events.append((latency_ns, pkt_len))
            i += 3
        else:
            i += 1
    return events


def percentile(sorted_vals, p):
    if not sorted_vals:
        return 0
    k = (len(sorted_vals) - 1) * (p / 100.0)
    f = int(k)
    c = min(f + 1, len(sorted_vals) - 1)
    if f == c:
        return sorted_vals[f]
    return sorted_vals[f] + (sorted_vals[c] - sorted_vals[f]) * (k - f)


if __name__ == '__main__':
    path = sys.argv[1] if len(sys.argv) > 1 else 'latency_events_raw.txt'
    events = parse(path)
    lat = sorted(e[0] for e in events)
    n = len(lat)
    print(f"samples: {n}")
    if n == 0:
        sys.exit(0)
    print(f"min_ns: {lat[0]}")
    print(f"mean_ns: {sum(lat)/n:.1f}")
    for p in (50, 90, 99, 99.9):
        print(f"p{p}_ns: {percentile(lat, p):.1f}")
    print(f"max_ns: {lat[-1]}")
    # Sanity: pkt_len should be constant for a fixed-size synthetic test.
    lens = set(e[1] for e in events)
    print(f"distinct pkt_len values observed: {sorted(lens)}")
