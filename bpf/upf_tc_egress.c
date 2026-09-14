// SPDX-License-Identifier: GPL-2.0
// upf_tc_egress.c — TC egress programme: downlink GTP-U encapsulation.
//
// Attaches to the clsact/egress hook of the N3-facing interface. A plain
// (not-yet-encapsulated) IPv4 packet destined for a known UE address is
// intercepted just before it leaves the interface, wrapped in a fresh
// outer IP/UDP/GTP-U header built from dl_ue_map (TEID, gNB address, QFI),
// and let continue its transmission out the same interface -- unlike the
// ingress/FAR_FORWARD path, no bpf_redirect() is needed here since the
// hook is already positioned on the correct egress interface (this models
// TC egress on N3 per the paper's Option A; Option B's placement on N6
// would instead need a redirect to N3, which is a straightforward
// variant of this same encapsulation logic).

#include "upf_maps.h"
#include <bpf/bpf_endian.h>

#define TC_ACT_OK_X         0
#define TC_ACT_SHOT_X       2

#define ETH_P_IP_X      0x0800
#define IPPROTO_UDP_X   17
#define GTPU_PORT_X     2152

#define BPF_ADJ_ROOM_MAC_X               1
#define BPF_F_ADJ_ROOM_FIXED_GSO_X       (1ULL << 0)

/* Standard Internet checksum over a fixed 20-byte (10 x u16) IPv4 header
 * with ip->check already zeroed by the caller. Fixed trip count so the
 * verifier can bound it trivially. */
static __always_inline __u16 ip_checksum20(void *hdr)
{
    __u16 *p = hdr;
    __u32 sum = 0;
#pragma unroll
    for (int i = 0; i < 10; i++)
        sum += p[i];
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    return (__u16)~sum;
}

SEC("classifier")
int upf_tc_egress(struct __sk_buff *skb)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK_X;
    if (eth->h_proto != bpf_htons(ETH_P_IP_X))
        return TC_ACT_OK_X;    /* not IPv4: nothing for us to encapsulate */

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK_X;

    /* Already a GTP-U packet (e.g. one we just admitted on the ingress
     * side and are now seeing again on egress via the self-loop testbed)?
     * Don't try to double-encapsulate it. */
    if (ip->protocol == IPPROTO_UDP_X) {
        __u32 ihl_bytes = ip->ihl * 4;
        void *l4 = (void *)ip + ihl_bytes;
        struct udphdr *udp = l4;
        if ((void *)(udp + 1) <= data_end && udp->dest == bpf_htons(GTPU_PORT_X))
            return TC_ACT_OK_X;
    }

    __u32 dst_ip = ip->daddr;    /* network byte order, matches dl_ue_map key convention */

    struct dl_ue_val *ue = bpf_map_lookup_elem(&dl_ue_map, &dst_ip);
    if (!ue) {
        bump(M_TC_DL_MISS);
        return TC_ACT_OK_X;    /* not a UE we have downlink state for; leave untouched */
    }
    bump(M_TC_DL_HIT);

    __u32 cfg_key = 0;
    struct upf_config *cfg = bpf_map_lookup_elem(&upf_config_map, &cfg_key);
    __u32 n3_addr_be = cfg ? cfg->n3_addr_be : 0;

    __u32 add_len = (__u32)sizeof(struct iphdr) + (__u32)sizeof(struct udphdr) + 8;
    __u64 flags = BPF_F_ADJ_ROOM_FIXED_GSO_X;

    if (bpf_skb_adjust_room(skb, (int)add_len, BPF_ADJ_ROOM_MAC_X, flags) < 0) {
        bump(M_TC_DL_ENCAP_ERR);
        return TC_ACT_SHOT_X;
    }

    /* Packet grew: data/data_end pointers above are stale, must re-derive. */
    data     = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;

    eth = data;
    if ((void *)(eth + 1) > data_end) {
        bump(M_TC_DL_ENCAP_ERR);
        return TC_ACT_SHOT_X;
    }
    struct iphdr *outer_ip = (void *)(eth + 1);
    if ((void *)(outer_ip + 1) > data_end) {
        bump(M_TC_DL_ENCAP_ERR);
        return TC_ACT_SHOT_X;
    }
    struct udphdr *outer_udp = (void *)(outer_ip + 1);
    if ((void *)(outer_udp + 1) > data_end) {
        bump(M_TC_DL_ENCAP_ERR);
        return TC_ACT_SHOT_X;
    }
    void *gtp = (void *)(outer_udp + 1);
    if (gtp + 8 > data_end) {
        bump(M_TC_DL_ENCAP_ERR);
        return TC_ACT_SHOT_X;
    }

    __u32 total_len = skb->len - (__u32)sizeof(struct ethhdr);
    __u32 udp_len   = total_len - (__u32)sizeof(struct iphdr);
    __u32 gtp_paylen = udp_len - (__u32)sizeof(struct udphdr) - 8;

    outer_ip->version  = 4;
    outer_ip->ihl      = 5;
    outer_ip->tos      = 0;
    outer_ip->tot_len  = bpf_htons((__u16)total_len);
    outer_ip->id       = 0;
    outer_ip->frag_off = 0;
    outer_ip->ttl      = 64;
    outer_ip->protocol = IPPROTO_UDP_X;
    outer_ip->check    = 0;
    outer_ip->saddr    = n3_addr_be;
    outer_ip->daddr    = ue->gnb_ipv4_be;
    outer_ip->check    = ip_checksum20(outer_ip);

    outer_udp->source = bpf_htons(GTPU_PORT_X);
    outer_udp->dest   = bpf_htons(GTPU_PORT_X);
    outer_udp->len    = bpf_htons((__u16)udp_len);
    outer_udp->check  = 0;    /* optional for IPv4/UDP; 0 = checksum not computed (RFC 768) */

    __u8 gtp_flags = 0x30;    /* version 1, protocol type 1 (GTP, not GTP') */
    __u8 gtp_type  = 0xff;    /* G-PDU */
    __builtin_memcpy(gtp + 0, &gtp_flags, 1);
    __builtin_memcpy(gtp + 1, &gtp_type, 1);
    __u16 gtp_len_be = bpf_htons((__u16)gtp_paylen);
    __builtin_memcpy(gtp + 2, &gtp_len_be, 2);
    __builtin_memcpy(gtp + 4, &ue->teid_be, 4);

    return TC_ACT_OK_X;    /* already egressing the right interface; let it go */
}

char _license[] SEC("license") = "GPL";
