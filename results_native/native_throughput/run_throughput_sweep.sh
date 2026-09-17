#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
OUT=results_native/native_throughput/throughput_raw.txt
: > "$OUT"
for fb in 64 1500; do
  for n in 1 2 4; do
    for r in 1 2 3; do
      python3 test/native_throughput.py --nthreads $n --duration 5 --frame-bytes $fb | tee -a "$OUT"
    done
  done
done
echo "[+] sweep complete -> $OUT"
