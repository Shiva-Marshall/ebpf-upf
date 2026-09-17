// SPDX-License-Identifier: GPL-2.0
// upf_tc.c — TC ingress programme: PDR/FAR enforcement + GTP-U decapsulation.
//
// Attaches to the clsact/ingress hook of the same interface the XDP
// programme runs on. By the time a packet reaches here via XDP_PASS, XDP
// has already dropped every G-PDU packet with an unresolvable TEID or PDR
// (see upf_xdp.c) -- so only three kinds of traffic arrive: non-GTP UDP,
// GTP-U control messages, and known-TEID G-PDU traffic. This programme
// re-parses the packet and re-derives TEID/session/PDR/FAR independently
// of XDP rather than relying on skb->cb[]/metadata propagation from XDP
// (which is driver- and kernel-version-dependent); the extra hash lookups
// are O(1) and this keeps the two hooks decoupled and independently
// testable, at the cost of parsing the header twice. A TC-side miss can
// only happen if map state changed between the XDP and TC lookups (a race
// with a concurrent PFCP rule update, see Section on transactional
// consistency) -- we count it but do not drop, since we cannot
// distinguish a benign race from anything adversarial at this layer, and
// dropping would be strictly worse than letting the kernel stack see the
// packet unmodified.

#include "upf_maps.h"
#include <bpf/bpf_endian.h>

/* struct ethhdr/iphdr/udphdr already come from vmlinux.h (BTF-derived);
 * including the regular linux/if_ether.h & co. on top conflicts with those
 * definitions, so we only pull in the handful of TC_ACT_* macros we need
 * (normally from linux/pkt_cls.h) rather than the whole header. */
#define TC_ACT_OK_X         0
#define TC_ACT_SHOT_X       2
#define TC_ACT_REDIRECT_X   7
#define BPF_F_CURRENT_CPU_X 0xffffffffULL

#define ETH_P_IP_X      0x0800
#define IPPROTO_UDP_X   17
#define GTPU_PORT_X     2152
#define GTPU_GPDU_X     0xff
#define BPF_ADJ_ROOM_MAC_X            1  /* was NET_X=0: adjusts below L3, kept stale outer IP header */
#define BPF_F_ADJ_ROOM_FIXED_GSO_X    (1ULL << 0)

/* Token-bucket admission check for QER `qer_id` against `pkt_len` bytes.
 * Returns 1 (admit) or 0 (exceeds configured MBR, caller should drop).
 * Two implementations are provided and selected at build time: a per-CPU
 * bucket (default) and a shared spin-locked bucket
 * (-DUPF_QER_SHARED_LOCK). See the qer_bucket_state comment in upf_maps.h
 * for the accuracy/contention trade-off that motivates measuring both. */
#ifdef UPF_QER_SHARED_LOCK
/* Shared-bucket variant: one global token bucket per QER, guarded by a
 * bpf_spin_lock, so an MBR is enforced in aggregate across all CPUs rather
 * than per-CPU. Same arithmetic as the per-CPU path below; the only
 * difference is where the state lives and that access is serialised. */
static __always_inline int upf_qer_admit(__u32 qer_id, __u32 pkt_len)
{
    struct qer_val *qv = bpf_map_lookup_elem(&qer_table, &qer_id);
    if (!qv || qv->mbr_ul_bps == 0)
        return 1;

    struct qer_bucket_locked *st = bpf_map_lookup_elem(&qer_state_shared, &qer_id);
    if (!st)
        return 1;

    __u64 now = bpf_ktime_get_ns();
    int admit;

    bpf_spin_lock(&st->lock);
    if (st->last_ns == 0) {
        st->tokens_bytes = qv->burst_bytes;
        st->last_ns = now;
    } else {
        /* `now` is sampled before the lock is taken, because the verifier
         * forbids calling helpers inside a spin-lock critical section. Under
         * contention that means CPUs can acquire the lock out of timestamp
         * order: a CPU that sampled an earlier `now` may enter after one that
         * sampled a later one, leaving now < last_ns. On __u64 that subtraction
         * wraps to an enormous value, which the clamp below then turns into a
         * full-bucket refill -- measured as a ~3x MBR overshoot before this
         * guard was added, i.e. the shared bucket silently lost the very rate
         * enforcement it exists to provide. Treat out-of-order arrivals as
         * contributing no elapsed time instead. */
        __u64 elapsed = (now > st->last_ns) ? (now - st->last_ns) : 0;
        if (elapsed > 1000000000ULL)
            elapsed = 1000000000ULL;
        __u64 refill = (elapsed * qv->mbr_ul_bps) / 8000000000ULL;
        st->tokens_bytes += refill;
        if (st->tokens_bytes > qv->burst_bytes)
            st->tokens_bytes = qv->burst_bytes;
        st->last_ns = now;
    }
    if (st->tokens_bytes >= pkt_len) {
        st->tokens_bytes -= pkt_len;
        admit = 1;
    } else {
        admit = 0;
    }
    bpf_spin_unlock(&st->lock);

    return admit;
}
#else
static __always_inline int upf_qer_admit(__u32 qer_id, __u32 pkt_len)
{
    struct qer_val *qv = bpf_map_lookup_elem(&qer_table, &qer_id);
    if (!qv || qv->mbr_ul_bps == 0)
        return 1;    /* no QER configured / unlimited: admit */

    struct qer_bucket_state *st = bpf_map_lookup_elem(&qer_state, &qer_id);
    if (!st)
        return 1;    /* qer_id out of range for qer_state: fail open */

    __u64 now = bpf_ktime_get_ns();
    if (st->last_ns == 0) {
        /* First-ever use of this bucket: start full so the first burst
         * up to burst_bytes is never penalised by an artificially empty
         * bucket. */
        st->tokens_bytes = qv->burst_bytes;
        st->last_ns = now;
    } else {
        __u64 elapsed = now - st->last_ns;
        if (elapsed > 1000000000ULL)
            elapsed = 1000000000ULL;   /* cap refill window; bounds the multiply below and the
                                         * bucket saturates at burst_bytes well before 1s anyway */
        __u64 refill = (elapsed * qv->mbr_ul_bps) / 8000000000ULL;  /* bits/sec -> bytes over elapsed */
        st->tokens_bytes += refill;
        if (st->tokens_bytes > qv->burst_bytes)
            st->tokens_bytes = qv->burst_bytes;
        st->last_ns = now;
    }

    if (st->tokens_bytes >= pkt_len) {
        st->tokens_bytes -= pkt_len;
        return 1;
    }
    return 0;
}
#endif /* UPF_QER_SHARED_LOCK */

/* Usage accounting for URR `urr_id`. Per-CPU hash: each CPU maintains its
 * own counters for a given URR id, aggregated by the PFCP agent at
 * reporting time (Section on observability); no cross-CPU synchronisation
 * needed on the increment path. */
static __always_inline void upf_urr_update(__u32 urr_id, __u32 pkt_len)
{
    if (urr_id == 0)
        return;    /* 0 = no URR configured for this PDR */

    struct urr_val *uv = bpf_map_lookup_elem(&urr_counters, &urr_id);
    if (uv) {
        uv->bytes_ul += pkt_len;
        uv->pkts_ul  += 1;
    } else {
        struct urr_val init = { .bytes_ul = pkt_len, .pkts_ul = 1 };
        /* BPF_NOEXIST: if another packet on this CPU already raced us to
         * create this key between lookup and here, our update is lost --
         * a rare, one-time bootstrap race affecting at most one packet's
         * count per (urr_id, CPU) pair, acceptable for this prototype. */
        bpf_map_update_elem(&urr_counters, &urr_id, &init, BPF_NOEXIST);
    }
    bump(M_TC_URR_UPDATED);
}

/* Strip `outer_hdr_len` bytes of outer IP/UDP/GTP-U header (leaving the
 * Ethernet header and the inner IP packet intact), apply QER policing and
 * URR accounting to the decapsulated inner packet, then redirect out the
 * FAR's configured egress interface. */
static __always_inline int upf_far_forward(struct __sk_buff *skb,
                                            __u32 far_id, __u32 qer_id, __u32 urr_id,
                                            __u32 pdr_id, __u32 generation,
                                            __u32 outer_hdr_len)
{
    if (bpf_skb_adjust_room(skb, -(int)outer_hdr_len, BPF_ADJ_ROOM_MAC_X,
                             BPF_F_ADJ_ROOM_FIXED_GSO_X) < 0) {
        bump(M_TC_DECAP_ERR);
        return TC_ACT_SHOT_X;
    }

    struct far_val *far = bpf_map_lookup_elem(&far_table, &far_id);
    if (!far) {
        /* far_table entry vanished mid-flight (concurrent delete) */
        bump(M_TC_DECAP_ERR);
        return TC_ACT_SHOT_X;
    }

    __u32 pkt_len = skb->len;   /* inner (decapsulated) packet length */

    if (!upf_qer_admit(qer_id, pkt_len)) {
        bump(M_TC_QER_DROP);
        return TC_ACT_SHOT_X;
    }
    bump(M_TC_QER_PASS);

    upf_urr_update(urr_id, pkt_len);

#ifdef UPF_EMIT_DECISION_EVENTS
    struct decision_event dev = {
        .far_id = far_id, .qer_id = qer_id, .generation = generation, .pdr_id = pdr_id,
    };
    bpf_perf_event_output(skb, &perf_events, BPF_F_CURRENT_CPU_X, &dev, sizeof(dev));
#else
    (void)generation; (void)pdr_id;
#endif

    bump(M_TC_FAR_FORWARD);
    int ret = bpf_redirect(far->out_ifindex, 0);
    if (ret != TC_ACT_REDIRECT_X)
        bump(M_TC_REDIRECT_ERR);
    return ret;
}

SEC("classifier")
int upf_tc_ingress(struct __sk_buff *skb)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK_X;
    if (eth->h_proto != bpf_htons(ETH_P_IP_X))
        return TC_ACT_OK_X;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK_X;
    if (ip->protocol != IPPROTO_UDP_X)
        return TC_ACT_OK_X;

    __u32 ihl_bytes = ip->ihl * 4;
    if (ihl_bytes < sizeof(*ip))
        return TC_ACT_OK_X;
    void *l4 = (void *)ip + ihl_bytes;
    if (l4 + sizeof(struct udphdr) > data_end)
        return TC_ACT_OK_X;

    struct udphdr *udp = l4;
    if (udp->dest != bpf_htons(GTPU_PORT_X))
        return TC_ACT_OK_X;       /* non-GTP: not ours, leave for the stack */

    void *gtp = (void *)(udp + 1);
    if (gtp + 8 > data_end)
        return TC_ACT_OK_X;
    __u8 msg_type = *(__u8 *)(gtp + 1);
    if (msg_type != GTPU_GPDU_X)
        return TC_ACT_OK_X;       /* GTP-U control: not ours */

    __u32 teid_be;
    __builtin_memcpy(&teid_be, gtp + 4, 4);
    __u32 teid = bpf_ntohl(teid_be);

    struct session_val *sess = bpf_map_lookup_elem(&teid_session, &teid);
    if (!sess) {
        bump(M_TC_MISS_FAR);
        return TC_ACT_OK_X;       /* race with a concurrent rule update */
    }

    /* Single atomic whole-value read: transactional-consistency mechanism,
     * see the tc_bundle comment in upf_maps.h. Whichever slot `active`
     * names is a complete, self-consistent (far_id, qer_id, urr_id,
     * precedence) tuple as of one Session Modification -- never a mix of
     * fields from two different modifications. */
    struct tc_bundle *bundle = bpf_map_lookup_elem(&tc_bundle_map, &sess->pdr_id);
    if (!bundle) {
        bump(M_TC_MISS_FAR);
        return TC_ACT_OK_X;
    }
    __u32 active = bundle->active & 1;    /* mask: verifier needs a provably-bounded index */
    struct tc_bundle_slot *cur = &bundle->slot[active];

    struct far_val *far = bpf_map_lookup_elem(&far_table, &cur->far_id);
    if (!far) {
        bump(M_TC_MISS_FAR);
        return TC_ACT_OK_X;
    }

    if (far->action == FAR_DROP) {
        bump(M_TC_FAR_DROP);
        return TC_ACT_SHOT_X;
    }

    if (far->action == FAR_BUFFER) {
        /* bpf_sk_redirect_map() (the paper's stated mechanism for handing
         * this packet to a userspace socket) is not a valid call from a
         * TC/classifier programme -- verified empirically, the verifier
         * rejects it outright ("unknown func"), it is restricted to
         * BPF_PROG_TYPE_SK_SKB/SK_MSG. See the buffer_event comment in
         * upf_maps.h for the mechanism actually used instead: notify via
         * perf event, drop the packet at the kernel layer. */
        struct buffer_event ev = {
            .teid    = teid,
            .pdr_id  = sess->pdr_id,
            .far_id  = cur->far_id,
            .pkt_len = skb->len,
            .ts_ns   = bpf_ktime_get_ns(),
        };
        bpf_perf_event_output(skb, &perf_events, BPF_F_CURRENT_CPU_X, &ev, sizeof(ev));
        bump(M_TC_FAR_BUFFER);
        return TC_ACT_SHOT_X;
    }

    /* FAR_FORWARD: strip the outer IP/UDP/GTP-U header, apply QER/URR,
     * then redirect. */
    __u32 outer_hdr_len = ihl_bytes + (__u32)sizeof(struct udphdr) + 8;
    return upf_far_forward(skb, cur->far_id, cur->qer_id, cur->urr_id,
                            sess->pdr_id, cur->generation, outer_hdr_len);
}

char _license[] SEC("license") = "GPL";
