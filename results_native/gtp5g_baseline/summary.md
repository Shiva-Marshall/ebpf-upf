# gtp5g Baseline — Module Lifecycle and Control-Plane Crash Finding

Testbed: same native-XDP bare-metal host used throughout Section "Prototype
Implementation and Empirical Evaluation" (kernel 5.15.0-1079-realtime,
PREEMPT_RT, Intel XXV710/i40e). gtp5g built from free5gc/gtp5g source,
v0.10.2, against this exact running kernel.

## What worked cleanly

1. `insmod gtp5g.ko` — clean, two independent load cycles across two
   sessions, `dmesg` shows only the expected unsigned-out-of-tree-module
   taint warnings, no anomalies.
2. Device creation via raw rtnetlink (`gtp5g_link_add.py`) — `ip link add
   type gtp5g` and pyroute2 `kind="gtp5g"` both fail with `EINVAL` because
   gtp5g requires a mandatory `IFLA_GTP5G_FD1` (bound UDP socket fd)
   attribute neither tool can supply. Hand-built netlink message succeeds;
   verified via `ip link show` and the kernel's own
   "Registered a new 5G GTP interface" log line.
3. FAR installation via gtp5g's generic-netlink control API
   (`gtp5g_genl.py ... far_drop`) — minimal single-FAR add (link ifindex +
   FAR ID + DROP apply-action, no forwarding-parameter nesting) — succeeded
   cleanly. `dmesg` cleared immediately beforehand showed nothing after;
   server liveness (`uptime`) unaffected.

## What crashed the kernel

The very next call in the sequence, `gtp5g_genl.py ... pdr` — a PDR-add
referencing the FAR just installed, carrying a normal, well-formed PDI
(UE address, F-TEID with I-TEID + peer GTP-U address, source interface)
plus outer-header-removal and FAR-ID, exactly the attribute set a real
PFCP Session Establishment would produce — caused an immediate, silent
hard reboot:

- `dmesg -C` run immediately before the call; the SSH session then
  terminated with "client_loop: send disconnect: Broken pipe" (exit 255).
- A fresh SSH connection ~90s later succeeded; `uptime` showed the machine
  up for 1 minute — a hard reboot had occurred.
- `journalctl --list-boots` (`boots_list.txt`) confirms a boot boundary at
  the moment of the crash.
- `journalctl -b -1` (the crashed boot's own log, `crashed_boot_tail.txt`)
  shows regular periodic service output (ptp4l/phc2sys clock-sync
  messages, ~125ms cadence) right up to an abrupt cutoff — no panic
  message, no oops, no BUG trace, no orderly shutdown sequence. The log
  simply stops mid-stream.
- No crash dump was captured: `/sys/fs/pstore` is empty and
  `kdump`/`kdump-tools` are inactive on this host, so no kernel oops/panic
  record survives the reboot. We therefore cannot cite an exact faulting
  function from a stack trace.

## Why we did not bisect further

We deliberately stopped after this single, cleanly isolated reproduction
(module load → device up → FAR add all logged clean; the very next call,
and only that call, produced the crash) rather than attempting to narrow
down which specific nested attribute is responsible. This is shared,
multi-user research infrastructure (other login sessions exist on the
host), and each further reproduction attempt costs an unplanned reboot
for other users. We consider one clean, single-variable reproduction
sufficient to report the finding; we do not claim a confirmed root cause
at the source-line level.

An earlier, less cleanly isolated reboot occurred two days prior during
initial development of this same script; at the time we attributed it to
unrelated automated infrastructure reprovisioning (a Kubernetes/Cilium
deployment on the same host reappeared on its own after that reboot, via
external fleet-management automation, independent of our actions). In
light of this cleanly isolated reproduction, that earlier incident more
plausibly shares the same root cause, though this cannot be confirmed
retroactively (the script file involved was itself found zeroed on disk
after that reboot — consistent with ext4 delayed-allocation data loss on
an unclean shutdown, i.e. collateral damage of the crash rather than
independent evidence about its cause).

## Plausible structural cause (source-read, not stack-trace-confirmed)

`src/genl/genl.c` registers each generic-netlink command with its
`.policy` field commented out for every PDR/FAR/QER/URR operation:

```c
static const struct nla_policy gtp5g_genl_pdr_policy[GTP5G_PDR_ATTR_MAX + 1] = { ... };
...
    // .policy = gtp5g_genl_pdr_policy,
```

This means the kernel's generic-netlink layer performs no automatic
attribute presence/type validation before invoking gtp5g's handlers —
validation is left entirely to ad hoc `info->attrs[...]` NULL checks
written by hand inside each handler. We reviewed `gtp5g_genl_add_pdr()`,
`pdr_fill()`, `parse_pdi()`, and `parse_f_teid()` directly and did not
find an obviously unguarded dereference for the specific attribute set
this script sends, which suggests the fault (if triggered by our input
at all, rather than by unrelated state) lies deeper in the module — most
likely in the FAR/URR/QER cross-reference or hash-table update path that
`pdr_fill()` invokes once a PDR successfully references a real FAR
(`far_set_pdr()`, `urr_set_pdr()`, `qer_set_pdr()`,
`pdr_update_hlist_table()`), not in the netlink attribute parsing itself.
This is a plausible explanation consistent with the missing policy
validation, not a confirmed one.

## Files in this directory

- `gtp5g_genl.py` — the genl client (family resolution, `add_far`,
  `add_pdr`), rewritten cleanly this session; attribute IDs verified
  directly against the kernel module's own headers.
- `gtp5g_link_add.py` — raw rtnetlink device-creation client.
- `boots_list.txt`, `crashed_boot_tail.txt` — journal evidence.
- `gtp5g_modinfo.txt`, `kernel_version.txt` — environment record.
