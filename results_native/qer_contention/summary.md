# QER Lock Contention — per-CPU vs Shared Spin-Locked Token Bucket

Addresses Reviewer 2 point 4 ("analyze how lock contention is managed in the
QER token-bucket rate limiter during high concurrent traffic") and Reviewer 1's
related observation that "shared-QER state can create lock contention while
per-CPU buckets can temporarily violate the configured rate."

Both bucket strategies are implemented in `bpf/upf_tc.c` behind a build-time
switch (`-DUPF_QER_SHARED_LOCK`), so the same datapath, the same traffic, and
the same hardware are used for both arms.

## Result

See `summary.txt` for the table. In short:

* **Per-CPU bucket**: overshoot tracks the number of engaged CPUs almost
  exactly (0.96x at 1 core, 4.06x at 4, 15.29x at 16). Each CPU refills its
  own bucket against the *same* configured MBR, so an aggregate MBR is
  enforced N times over. Cheapest per packet (130-161 ns).
* **Shared spin-locked bucket**: enforces the MBR at every concurrency level
  (0.79-0.95x), at 12-45% higher per-packet cost (146-201 ns).

The per-CPU arm is not merely "approximate" — at 16 cores it admits fifteen
times the configured rate, which for a per-slice aggregate MBR is a
QoS-correctness failure, not a rounding error.

The shared arm slightly *under*-enforces (0.79x at 16 queues). This is the
integer-truncation bias in the refill arithmetic: `refill = elapsed * mbr /
8e9` truncates toward zero on every acquisition while `last_ns` always
advances, so credit is lost in proportion to how often the bucket is touched.
It is reported as measured rather than tuned away.

## Methodology note: concurrency is a controlled variable

An earlier sweep (`raw.txt`) varied the *flow count* and recorded how many
CPUs happened to be engaged. That was a design flaw: RSS hashing made the
engaged-CPU count vary between otherwise identical runs, so the independent
variable was being observed rather than set, and repeats were not comparable.
The reported sweep (`raw_queues.txt`) instead constrains concurrency directly
with `ethtool -L <iface> combined N`. Because changing the queue count resets
the NIC and tears down attached XDP/TC programmes, the datapath is reloaded
and the agent restarted after every change.

## A real bug the experiment exposed

The shared bucket initially produced erratic overshoot (0.8x to 7.7x across
runs) — impossible for a correctly serialised global bucket. The cause was a
genuine concurrency bug in our implementation, not measurement noise:

`bpf_ktime_get_ns()` must be sampled *before* `bpf_spin_lock()`, because the
verifier forbids helper calls inside a spin-lock critical section. Under
contention, CPUs therefore acquire the lock out of timestamp order, and a CPU
that sampled an earlier `now` can enter after one that sampled a later one,
leaving `now < last_ns`. On `__u64` that subtraction wraps to an enormous
value, which the existing one-second clamp then converts into a *full bucket
refill*. The shared bucket silently lost the rate enforcement it exists to
provide, measured at ~3.2x MBR overshoot.

The fix treats out-of-order arrivals as contributing no elapsed time:

```c
__u64 elapsed = (now > st->last_ns) ? (now - st->last_ns) : 0;
```

After the fix, enforcement is accurate and highly reproducible: three
consecutive 32-flow runs admitted 1.804, 1.805 and 1.803 Mbps against a
2 Mbps configured MBR.

This is worth recording for the same reason as the `agent.py` subprocess
defect found during the eUPF comparison: the naive expectation is that the
shared-lock design is the "safe, correct" option and the per-CPU design is the
"fast, approximate" one. In practice the shared design has a correctness trap
that only manifests under genuine multi-core contention — which is precisely
the regime it exists to handle, and precisely the regime a single-core
functional test would never reach.

## Files

* `raw_queues.txt` — the reported sweep (queue count controlled).
* `raw.txt` — earlier flow-count sweep; retained because it is what exposed
  the bug above. Superseded as a result.
* `summary.txt` — aggregated table.
* Harness: `test/qer_contention.py`, `test/qer_contention_sweep.sh`,
  `test/qer_blast.c` (multi-flow generator that varies the outer UDP source
  port so RSS actually spreads flows across receive CPUs — varying only the
  TEID leaves every packet on one queue, since RSS does not hash GTP payload).
