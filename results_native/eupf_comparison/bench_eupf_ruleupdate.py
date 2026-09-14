#!/usr/bin/env python3
"""Rule-update latency benchmark for eUPF via its REST API, for direct
comparison against our own bench_rule_update.c (which times at the bpf()
syscall level). This measures a higher layer (HTTP + JSON + cilium/ebpf
Put()), which is the closest comparable operation eUPF exposes without
modifying its source -- methodology difference to be disclosed
explicitly, not hidden."""
import sys, time, json
import urllib.request

BASE = "http://127.0.0.1:8080/api/v1"

def put_pdr(pdr_id, far_id=2, qer_id=0):
    body = json.dumps({
        "id": pdr_id, "outer_header_removal": 1, "far_id": far_id, "qer_id": qer_id
    }).encode()
    req = urllib.request.Request(f"{BASE}/uplink_pdr_map/{pdr_id}", data=body,
                                  method="PUT", headers={"Content-Type": "application/json"})
    urllib.request.urlopen(req, timeout=5).read()

def bench(n, base_id=20000):
    samples_us = []
    t_start = time.monotonic_ns()
    for i in range(n):
        s = time.monotonic_ns()
        put_pdr(base_id + i)
        e = time.monotonic_ns()
        samples_us.append((e - s) / 1000.0)
    t_end = time.monotonic_ns()
    total_ms = (t_end - t_start) / 1e6
    mean_us = sum(samples_us) / n
    ss = sorted(samples_us)
    def pct(p):
        idx = int(p * (n - 1))
        return ss[idx]
    print(f"N={n}  total={total_ms:.3f}ms  mean={mean_us:.3f}us  min={ss[0]:.3f}  "
          f"p50={pct(0.50):.3f}  p95={pct(0.95):.3f}  p99={pct(0.99):.3f}  max={ss[-1]:.3f}")
    return samples_us

if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 100
    bench(n)
