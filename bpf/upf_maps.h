// SPDX-License-Identifier: GPL-2.0
// upf_maps.h — shared BPF map definitions for the XDP and TC programmes.
//
// Maps are pinned by name under /sys/fs/bpf/upf so that upf_xdp.o (loaded
// first) and upf_tc.o (loaded second, same pin directory) resolve to the
// *same* map instances rather than each creating their own copy. This is
// the standard libbpf/bpftool "pin by name" pattern for state shared across
// independently-loaded BPF objects that cannot be a single compilation
// unit (XDP and TC/sched_cls are different program types and cannot
// tail-call into each other).

#ifndef UPF_MAPS_H
#define UPF_MAPS_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define MAX_TEIDS   65536
#define MAX_PDRS    4096
#define MAX_FARS    4096
#define MAX_QERS    4096
#define MAX_URRS    4096
#define MAX_DL_UES  65536

/* ------------- Shared value types (must match userspace agent) ------------- */

struct session_val {
    __u32 pdr_id;
    __u32 qer_id;
    __u32 far_id;
    __u32 _pad;
};

struct pdr_val {
    __u32 far_id;
    __u32 qer_id;
    __u32 precedence;
    __u32 urr_id;         /* 0 = no URR configured for this PDR */
};

/* FAR apply-action values, per 3GPP TS 29.244 Apply Action IE (Sec 8.2.26). */
enum far_action {
    FAR_DROP    = 0,
    FAR_FORWARD = 1,
    FAR_BUFFER  = 2,
};

struct far_val {
    __u32 action;        /* enum far_action */
    __u32 out_ifindex;   /* egress ifindex for FORWARD */
    __u32 peer_ipv4_be;  /* GTP-U peer address for re-encap (N3/N9 FAR) */
    __u32 out_teid_be;   /* TEID to stamp on outer GTP-U header, if re-encap */
};

struct qer_val {
    __u64 mbr_ul_bps;    /* uplink Maximum Bit Rate, bits/sec */
    __u64 mbr_dl_bps;    /* downlink Maximum Bit Rate, bits/sec */
    __u32 burst_bytes;   /* token-bucket burst size */
    __u32 _pad;
};

/* Dynamic per-QER token-bucket state, separate from the static qer_table
 * configuration above. One instance per CPU (BPF_MAP_TYPE_PERCPU_ARRAY):
 * each CPU refills and drains its own bucket independently, avoiding any
 * lock in the forwarding hot path. The direct consequence -- documented in
 * the paper's Discussion section -- is that a QER whose traffic is spread
 * across N CPUs (by RSS/multi-queue) can admit up to N times its
 * configured MBR in aggregate, since each CPU's bucket is refilled against
 * the *same* mbr_ul_bps independently rather than sharing one global
 * allowance. A shared, spin-lock-protected bucket (traded contention for
 * accuracy) is the alternative examined in the QER contention experiment. */
struct qer_bucket_state {
    __u64 tokens_bytes;
    __u64 last_ns;
};

struct urr_val {
    __u64 bytes_ul;
    __u64 bytes_dl;
    __u64 pkts_ul;
    __u64 pkts_dl;
};

struct dl_ue_val {
    __u32 teid_be;
    __u32 gnb_ipv4_be;
    __u16 qfi;
    __u16 _pad;
};

/* Emitted via perf_events for the FAR_BUFFER path. bpf_sk_redirect_map()
 * (which the paper describes for handing a BUFFER packet to a userspace
 * socket) is only a valid helper call from BPF_PROG_TYPE_SK_SKB/SK_MSG
 * programs -- verified empirically: loading it from this TC (SCHED_CLS)
 * programme is rejected outright by the verifier ("unknown func
 * bpf_sk_redirect_map"), not merely discouraged. True in-kernel packet
 * retention would need a custom ring-buffer hold/replay scheme, out of
 * scope here. The mechanism actually used -- notify control plane via a
 * compact perf event, drop the individual packet at the kernel layer --
 * matches common practice in real UPF implementations for the 3GPP
 * BUFFER action: the SMF pages the UE off the back of the Downlink Data
 * Notification this event enables, and delivery is retried once the PDR
 * is switched back to FORWARD, rather than the original dropped packet
 * itself being replayed from a kernel-held copy. */
struct buffer_event {
    __u32 teid;
    __u32 pdr_id;
    __u32 far_id;
    __u32 pkt_len;
    __u64 ts_ns;
};

enum metric_idx {
    M_RX_TOTAL = 0,
    M_RX_GTPU,
    M_RX_GPDU,
    M_HIT,
    M_MISS_TEID,
    M_MISS_PDR,
    M_PASS_NONGTP,
    M_PASS_CTRL,
    M_DROP_PARSE,
    /* TC-ingress stages, appended so existing XDP indices are unchanged. */
    M_TC_MISS_FAR,
    M_TC_FAR_DROP,
    M_TC_FAR_FORWARD,
    M_TC_FAR_BUFFER,
    M_TC_DECAP_ERR,
    M_TC_REDIRECT_ERR,
    M_TC_QER_PASS,
    M_TC_QER_DROP,
    M_TC_URR_UPDATED,
    /* TC-egress (downlink) stages. */
    M_TC_DL_HIT,
    M_TC_DL_MISS,
    M_TC_DL_ENCAP_ERR,
    M_MAX,
};

/* Tiny single-entry config map: the UPF's own N3-facing IPv4 address,
 * network byte order, used as the outer IP source when the TC egress
 * programme builds a new GTP-U encapsulation header. Populated by the
 * control plane at startup (key is always 0). */
struct upf_config {
    __u32 n3_addr_be;
};

/* ------------- Maps (all pinned by name -> shared across objects) ------------- */

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key,   __u32);     /* TEID (host order) */
    __type(value, struct session_val);
    __uint(max_entries, MAX_TEIDS);
} teid_session SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key,   __u32);     /* PDR id */
    __type(value, struct pdr_val);
    __uint(max_entries, MAX_PDRS);
} pdr_table SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key,   __u32);     /* FAR id */
    __type(value, struct far_val);
    __uint(max_entries, MAX_FARS);
} far_table SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key,   __u32);     /* QER id */
    __type(value, struct qer_val);
    __uint(max_entries, MAX_QERS);
} qer_table SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key,   __u32);     /* QER id, same key space as qer_table */
    __type(value, struct qer_bucket_state);
    __uint(max_entries, MAX_QERS);
} qer_state SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key,   __u32);     /* URR id */
    __type(value, struct urr_val);
    __uint(max_entries, MAX_URRS);
} urr_counters SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key,   __u32);     /* UE IPv4, network byte order */
    __type(value, struct dl_ue_val);
    __uint(max_entries, MAX_DL_UES);
} dl_ue_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key,   __u32);
    __type(value, __u64);
    __uint(max_entries, M_MAX);
} metrics SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key,   __u32);
    __type(value, struct upf_config);
    __uint(max_entries, 1);
} upf_config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __type(key,   __u32);     /* CPU index */
    __type(value, __u32);
} perf_events SEC(".maps");

static __always_inline void bump(__u32 idx)
{
    __u64 *v = bpf_map_lookup_elem(&metrics, &idx);
    if (v) __sync_fetch_and_add(v, 1);
}

#endif /* UPF_MAPS_H */
