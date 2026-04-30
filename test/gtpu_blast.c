// SPDX-License-Identifier: GPL-2.0
//
// gtpu_blast.c — generate a steady stream of GTP-U G-PDU packets at a
// configurable target rate via AF_PACKET. Used to load the XDP UPF prototype
// during zero-downtime rule-update tests.
//
// Build: gcc -O2 -Wall -o gtpu_blast gtpu_blast.c
// Usage: sudo ip netns exec upfns ./gtpu_blast <iface> <pps> <duration_s> <teid>

#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

struct __attribute__((packed)) ethhdr_x {
    uint8_t  dst[6], src[6];
    uint16_t proto;
};
struct __attribute__((packed)) iphdr_x {
    uint8_t  vihl, tos;
    uint16_t tot_len, id, frag_off;
    uint8_t  ttl, protocol;
    uint16_t check;
    uint32_t saddr, daddr;
};
struct __attribute__((packed)) udphdr_x {
    uint16_t source, dest, len, check;
};
struct __attribute__((packed)) gtphdr_x {
    uint8_t  flags, msg_type;
    uint16_t length;
    uint32_t teid;
};

static uint16_t ip_csum(void *data, int len) {
    uint32_t sum = 0;
    uint16_t *p = data;
    while (len >= 2) { sum += *p++; len -= 2; }
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return ~sum;
}

int main(int argc, char **argv)
{
    if (argc != 5) {
        fprintf(stderr, "usage: %s <iface> <pps> <duration_s> <teid_hex>\n", argv[0]);
        return 2;
    }
    const char *iface = argv[1];
    long pps          = atol(argv[2]);
    int  duration_s   = atoi(argv[3]);
    uint32_t teid     = (uint32_t)strtoul(argv[4], NULL, 0);

    int sk = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sk < 0) { perror("socket"); return 1; }

    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);
    if (ioctl(sk, SIOCGIFINDEX, &ifr) < 0) { perror("SIOCGIFINDEX"); return 1; }
    int ifindex = ifr.ifr_ifindex;
    if (ioctl(sk, SIOCGIFHWADDR, &ifr) < 0) { perror("SIOCGIFHWADDR"); return 1; }
    uint8_t src_mac[6];
    memcpy(src_mac, ifr.ifr_hwaddr.sa_data, 6);

    struct sockaddr_ll sa = {0};
    sa.sll_family   = AF_PACKET;
    sa.sll_protocol = htons(ETH_P_IP);
    sa.sll_ifindex  = ifindex;
    sa.sll_halen    = 6;
    memset(sa.sll_addr, 0xFF, 6);   // broadcast dst MAC

    /* Build packet once: Ether/IP/UDP(2152)/GTP-U(G-PDU)/inner-IP/payload (64B). */
    uint8_t buf[1500] = {0};
    int off = 0;
    struct ethhdr_x *eth = (void *)(buf + off); off += sizeof(*eth);
    memset(eth->dst, 0xFF, 6);
    memcpy(eth->src, src_mac, 6);
    eth->proto = htons(0x0800);

    struct iphdr_x *ip = (void *)(buf + off); off += sizeof(*ip);
    ip->vihl     = 0x45;
    ip->ttl      = 64;
    ip->protocol = 17;
    ip->saddr    = inet_addr("10.99.0.2");
    ip->daddr    = inet_addr("10.99.0.1");

    struct udphdr_x *udp = (void *)(buf + off); off += sizeof(*udp);
    udp->source = htons(2152);
    udp->dest   = htons(2152);
    udp->check  = 0;

    struct gtphdr_x *gtp = (void *)(buf + off); off += sizeof(*gtp);
    gtp->flags    = 0x30;        // version 1, PT 1
    gtp->msg_type = 0xff;        // G-PDU
    gtp->teid     = htonl(teid);

    /* Inner IP + 64-byte payload */
    struct iphdr_x *iip = (void *)(buf + off); off += sizeof(*iip);
    iip->vihl     = 0x45;
    iip->ttl      = 64;
    iip->protocol = 17;
    iip->saddr    = inet_addr("10.45.0.1");
    iip->daddr    = inet_addr("8.8.8.8");
    /* skip inner UDP fields, just stuff payload */
    memset(buf + off, 'X', 80);
    off += 80;

    /* Set lengths + checksums */
    int total_pkt   = off;
    int ip_total    = total_pkt - sizeof(*eth);
    int udp_total   = ip_total - sizeof(*ip);
    int gtp_payload = udp_total - sizeof(*udp) - sizeof(*gtp);
    int iip_total   = ip_total - sizeof(*ip) - sizeof(*udp) - sizeof(*gtp);
    ip->tot_len    = htons(ip_total);
    ip->check      = ip_csum(ip, sizeof(*ip));
    udp->len       = htons(udp_total);
    gtp->length    = htons(gtp_payload);
    iip->tot_len   = htons(iip_total);
    iip->check     = ip_csum(iip, sizeof(*iip));

    /* Pacing */
    long ns_per_pkt = pps > 0 ? 1000000000L / pps : 0;
    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);

    long sent = 0, errors = 0;
    long deadline_ns = (long)duration_s * 1000000000L;

    struct timespec t_next;
    clock_gettime(CLOCK_MONOTONIC, &t_next);

    while (1) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        long elapsed = (now.tv_sec - start.tv_sec) * 1000000000L +
                       (now.tv_nsec - start.tv_nsec);
        if (elapsed >= deadline_ns) break;

        ssize_t r = sendto(sk, buf, total_pkt, 0,
                           (struct sockaddr *)&sa, sizeof(sa));
        if (r < 0) errors++;
        else       sent++;

        if (ns_per_pkt > 0) {
            t_next.tv_nsec += ns_per_pkt;
            while (t_next.tv_nsec >= 1000000000L) {
                t_next.tv_nsec -= 1000000000L;
                t_next.tv_sec  += 1;
            }
            clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &t_next, NULL);
        }
    }

    struct timespec end;
    clock_gettime(CLOCK_MONOTONIC, &end);
    double dt = (end.tv_sec - start.tv_sec) +
                (end.tv_nsec - start.tv_nsec) / 1e9;
    fprintf(stderr, "blast: sent=%ld errors=%ld dt=%.3fs actual_pps=%.0f\n",
            sent, errors, dt, sent / dt);

    close(sk);
    return 0;
}
