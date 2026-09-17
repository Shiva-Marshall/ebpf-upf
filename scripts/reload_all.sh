#!/usr/bin/env bash
# Full reload of the three-programme datapath (XDP uplink + TC ingress + TC
# egress) with all maps shared across the independently-loaded objects.
#
# The explicit `map name X pinned ...` reuse syntax is required on this
# bpftool/libbpf version: a plain `pinmaps DIR` on the second and third
# loadall would try to re-pin maps that already exist and fail with EEXIST.
#
# Usage: sudo bash scripts/reload_all.sh [<iface>]
set -euo pipefail

IFACE="${1:-enp24s0f0}"
PIN=/sys/fs/bpf/upf
CD="$(cd "$(dirname "$0")/.." && pwd)"
cd "$CD"

# Shared maps that every object must reuse rather than re-create.
MAPS=(teid_session pdr_table far_table qer_table qer_state urr_counters
      dl_ue_map metrics upf_config_map perf_events tc_bundle_map)

reuse_args() {
    local out=()
    for m in "${MAPS[@]}"; do out+=(map name "$m" pinned "$PIN/$m"); done
    printf '%s\n' "${out[@]}"
}

echo "[*] detaching from $IFACE"
ip link set dev "$IFACE" xdp off 2>/dev/null || true
tc qdisc del dev "$IFACE" clsact 2>/dev/null || true

echo "[*] wiping $PIN"
rm -rf "$PIN"
mkdir -p "$PIN"

echo "[*] loading XDP (creates and pins all shared maps)"
bpftool prog loadall bpf/upf_xdp.o "$PIN/xdp_prog" pinmaps "$PIN"

echo "[*] loading TC ingress (reusing pinned maps)"
mapfile -t RA < <(reuse_args)
bpftool prog loadall bpf/upf_tc.o "$PIN/tc_prog" "${RA[@]}"

echo "[*] loading TC egress (reusing pinned maps)"
bpftool prog loadall bpf/upf_tc_egress.o "$PIN/tc_egress_prog" "${RA[@]}"

# Programmes pin under their SEC() name, not their C function name:
# SEC("xdp") -> xdp_prog/xdp, SEC("classifier") -> tc_prog/classifier.
echo "[*] attaching"
ip link set dev "$IFACE" xdp pinned "$PIN/xdp_prog/xdp"
tc qdisc add dev "$IFACE" clsact
tc filter add dev "$IFACE" ingress bpf da pinned "$PIN/tc_prog/classifier"
tc filter add dev "$IFACE" egress  bpf da pinned "$PIN/tc_egress_prog/classifier"

echo "[*] attached:"
ip link show "$IFACE" | grep -o 'xdp[a-z]*' | head -1
tc filter show dev "$IFACE" ingress | head -2
echo "[+] reload complete"
