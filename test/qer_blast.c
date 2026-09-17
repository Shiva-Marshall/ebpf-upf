// SPDX-License-Identifier: GPL-2.0
//
// qer_blast.c -- GTP-U generator for the QER lock-contention experiment.
//
// Differs from gtpu_blast.c in one way that matters for this experiment:
// it round-robins across <nflows> distinct flows, each with its own TEID
// *and* its own outer UDP source port. The source port is what makes this
// work: the receiving NIC's RSS hash covers (IP SA, IP DA, L4 sport, L4
// dport), so varying only the TEID would leave every packet on a single
// RX queue and therefore a single CPU, which is precisely the contention
// we are trying to create. Varying the outer source port spreads the
// flows across RX queues and hence across CPUs, while all of the
// corresponding PDRs still point at one shared QER.
//
// The sender stays single-threaded: RSS spreading happens on the receive
// side, so one sender core is sufficient to engage many receive CPUs.
//
// Build: gcc -O2 -Wall -o qer_blast qer_blast.c
// Usage: sudo ip netns exec upf_hw_test ./qer_blast <iface> <pps> <dur_s> <teid_base> <nflows>

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

#define MAX_FLOWS 64

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
    if (argc != 6) {
        fprintf(stderr, "usage: %s <iface> <pps> <duration_s> <teid_base_hex> <nflows>\n", argv[0]);
        return 2;
    }
    const char *iface = argv[1];
    long pps          = atol(argv[2]);
    int  duration_s   = atoi(argv[3]);
    uint32_t teid_base= (uint32_t)strtoul(argv[4], NULL, 0);
    int  nflows       = atoi(argv[5]);

    if (nflows < 1 || nflows > MAX_FLOWS) {
        fprintf(stderr, "nflows must be 1..%d\n", MAX_FLOWS);
        return 2;
    }

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
    memset(sa.sll_addr, 0xFF, 6);

    /* One pre-built packet per flow; only TEID and outer sport differ. */
    static uint8_t bufs[MAX_FLOWS][1500];
    int total_pkt = 0;

    for (int f = 0; f < nflows; f++) {
        uint8_t *buf = bufs[f];
        memset(buf, 0, 1500);
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
        /* Spread source ports widely so the RSS hash lands flows on
         * different queues; stride 7 avoids clustering in low bits. */
        udp->source = htons(30000 + f * 7);
        udp->dest   = htons(2152);
        udp->check  = 0;

        struct gtphdr_x *gtp = (void *)(buf + off); off += sizeof(*gtp);
        gtp->flags    = 0x30;
        gtp->msg_type = 0xff;
        gtp->teid     = htonl(teid_base + f);

        struct iphdr_x *iip = (void *)(buf + off); off += sizeof(*iip);
        iip->vihl     = 0x45;
        iip->ttl      = 64;
        iip->protocol = 17;
        iip->saddr    = inet_addr("10.45.0.1");
        iip->daddr    = inet_addr("8.8.8.8");
        memset(buf + off, 'X', 80);
        off += 80;

        int ip_total    = off - sizeof(*eth);
        int udp_total   = ip_total - sizeof(*ip);
        int gtp_payload = udp_total - sizeof(*udp) - sizeof(*gtp);
        int iip_total   = ip_total - sizeof(*ip) - sizeof(*udp) - sizeof(*gtp);
        ip->tot_len    = htons(ip_total);
        ip->check      = ip_csum(ip, sizeof(*ip));
        udp->len       = htons(udp_total);
        gtp->length    = htons(gtp_payload);
        iip->tot_len   = htons(iip_total);
        iip->check     = ip_csum(iip, sizeof(*iip));
        total_pkt = off;
    }

    long ns_per_pkt = pps > 0 ? 1000000000L / pps : 0;
    struct timespec start, t_next;
    clock_gettime(CLOCK_MONOTONIC, &start);
    clock_gettime(CLOCK_MONOTONIC, &t_next);

    long sent = 0, errors = 0;
    long deadline_ns = (long)duration_s * 1000000000L;
    int f = 0;

    for (;;) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        long elapsed = (now.tv_sec - start.tv_sec) * 1000000000L
                     + (now.tv_nsec - start.tv_nsec);
        if (elapsed >= deadline_ns) break;

        if (sendto(sk, bufs[f], total_pkt, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0)
            errors++;
        else
            sent++;

        f = (f + 1) % nflows;

        if (ns_per_pkt > 0) {
            t_next.tv_nsec += ns_per_pkt;
            while (t_next.tv_nsec >= 1000000000L) {
                t_next.tv_nsec -= 1000000000L;
                t_next.tv_sec++;
            }
            clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &t_next, NULL);
        }
    }

    printf("blast_sent=%ld blast_errors=%ld nflows=%d pkt_bytes=%d\n",
           sent, errors, nflows, total_pkt);
    return 0;
}
