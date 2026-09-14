#!/usr/bin/env python3
"""
toggle_bundle.py -- transactional-consistency concurrent-traffic experiment
driver (Section: transactional consistency).

Repeatedly, as fast as the control plane can issue it, atomically commits
tc_bundle_map[PDR_ID] to alternate between two distinct, distinguishable
(far_id, qer_id) pairs while traffic is flowing (run gtpu_blast
concurrently against the same PDR's TEID). Each committed generation is
recorded implicitly via the decision_event perf events a
UPF_EMIT_DECISION_EVENTS build emits per forwarded packet; see
results_native/transactional_consistency/analyze.py for verifying that no
packet observed a torn (invalid) pair.

Usage: sudo python3 toggle_bundle.py [duration_s]
"""
import os, sys, time
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from loader.agent import modify_tc_bundle

def main():
    duration = float(sys.argv[1]) if len(sys.argv) > 1 else 8.0
    pdr_id = 0x2000
    pairs = [(1, 1), (3, 3)]
    i = 0
    t_end = time.monotonic() + duration
    count = 0
    gen = None
    while time.monotonic() < t_end:
        far_id, qer_id = pairs[i % 2]
        gen = modify_tc_bundle(pdr_id, far_id=far_id, qer_id=qer_id)
        i += 1
        count += 1
    print(f"performed {count} bundle toggles, final generation={gen}", file=sys.stderr)


if __name__ == "__main__":
    main()
