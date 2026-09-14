// SPDX-License-Identifier: GPL-2.0
//
// bench_rule_update.c — measure end-to-end PFCP-rule install latency at the
// bpf() syscall level, by opening pinned maps and calling
// bpf_map_update_elem() in a tight loop.
//
// One "rule" = 1 pdr_table insert + 1 teid_session insert (mirrors what the
// PFCP agent does during a Session Establishment for a single PDR).
//
// Usage:
//   sudo ./bench_rule_update <n_rules> [csv_out_path]
//
// Output:
//   - one summary line on stdout: total/mean/min/p50/p95/p99/max are all
//     derived from the same per-rule samples[] array (total = sum(samples),
//     mean = total/n), so they reconcile exactly with each other and with
//     the released per-rule CSV; "wall" is a separate diagnostic -- the
//     true wall-clock span of the whole loop, which also includes
//     inter-iteration housekeeping not attributable to any single rule.
//   - if csv_out_path given, all per-rule samples in µs to that file (one
//     value per line) so we can plot the histogram for the paper.

#include <bpf/bpf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define PIN_BASE          "/sys/fs/bpf/upf"
#define PIN_TEID_SESSION  PIN_BASE "/teid_session"
#define PIN_PDR_TABLE     PIN_BASE "/pdr_table"

struct session_val {
    uint32_t pdr_id;
    uint32_t qer_id;
    uint32_t far_id;
    uint32_t _pad;
};

struct pdr_val {
    uint32_t far_id;
    uint32_t qer_id;
    uint32_t precedence;
    uint32_t _pad;
};

static int cmp_u64(const void *a, const void *b) {
    uint64_t aa = *(const uint64_t *)a, bb = *(const uint64_t *)b;
    return (aa > bb) - (aa < bb);
}

static uint64_t pct(uint64_t *sorted, int n, double p) {
    int idx = (int)(p * (n - 1));
    if (idx < 0) idx = 0;
    if (idx >= n) idx = n - 1;
    return sorted[idx];
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <n_rules> [csv_out_path]\n", argv[0]);
        return 2;
    }
    int n = atoi(argv[1]);
    if (n <= 0) { fprintf(stderr, "bad n\n"); return 2; }
    const char *csv = (argc >= 3) ? argv[2] : NULL;

    int fd_teid = bpf_obj_get(PIN_TEID_SESSION);
    if (fd_teid < 0) { perror("bpf_obj_get teid_session"); return 1; }
    int fd_pdr  = bpf_obj_get(PIN_PDR_TABLE);
    if (fd_pdr  < 0) { perror("bpf_obj_get pdr_table");    return 1; }

    uint64_t *samples = calloc(n, sizeof(uint64_t));
    if (!samples) { perror("calloc"); return 1; }

    /* Pre-pick keys outside the bootstrap range. */
    const uint32_t TEID_BASE = 0x10000;
    const uint32_t PDR_BASE  = 0x20000;

    /* Touch both maps once to warm any caches (paging the per-cpu values etc.) */
    {
        uint32_t k = 0xFFFFFFFE;
        struct pdr_val pv = { .far_id = 1, .qer_id = 1, .precedence = 1 };
        bpf_map_update_elem(fd_pdr, &k, &pv, BPF_ANY);
        bpf_map_delete_elem(fd_pdr, &k);
    }

    struct timespec t_start, t_end;
    clock_gettime(CLOCK_MONOTONIC, &t_start);

    for (int i = 0; i < n; i++) {
        uint32_t pdr_id = PDR_BASE  + i;
        uint32_t teid   = TEID_BASE + i;
        struct pdr_val     pv = { .far_id = 1, .qer_id = 1, .precedence = 100 };
        struct session_val sv = { .pdr_id = pdr_id, .qer_id = 1, .far_id = 1 };

        struct timespec a, b;
        clock_gettime(CLOCK_MONOTONIC, &a);

        if (bpf_map_update_elem(fd_pdr,  &pdr_id, &pv, BPF_ANY) < 0) {
            perror("update pdr"); free(samples); return 1;
        }
        if (bpf_map_update_elem(fd_teid, &teid,   &sv, BPF_ANY) < 0) {
            perror("update teid"); free(samples); return 1;
        }

        clock_gettime(CLOCK_MONOTONIC, &b);
        samples[i] = (uint64_t)(b.tv_sec - a.tv_sec) * 1000000000ULL +
                     (uint64_t)(b.tv_nsec - a.tv_nsec);
    }

    clock_gettime(CLOCK_MONOTONIC, &t_end);

    /* Sum of the per-rule samples: this is what "total"/"mean" below are
     * derived from, so they reconcile exactly with min/p50/p95/p99/max
     * (all computed from the same samples[] array) and with sum(update_us)
     * over the released per-rule CSV. We deliberately do NOT use
     * (t_end - t_start) for the reported total/mean: that wall-clock span
     * also includes inter-iteration housekeeping (the second clock_gettime()
     * call, loop bookkeeping, struct setup for the next iteration) that
     * never lands inside any individual samples[i], so it previously
     * inflated "total"/"mean" by ~15-25% relative to the percentiles
     * computed from the very same samples[] array -- reproducibly visible
     * even at n=1, where mean cannot legitimately differ from the one
     * recorded sample. That wall-clock figure is still worth keeping as a
     * separate diagnostic (it is the true throughput of running this loop),
     * so it is reported too, just not conflated with the per-rule stats.
     */
    uint64_t sum_ns = 0;
    for (int i = 0; i < n; i++) sum_ns += samples[i];

    /* Cleanup so repeat runs don't accumulate. */
    for (int i = 0; i < n; i++) {
        uint32_t pdr_id = PDR_BASE  + i;
        uint32_t teid   = TEID_BASE + i;
        bpf_map_delete_elem(fd_teid, &teid);
        bpf_map_delete_elem(fd_pdr,  &pdr_id);
    }

    /* Stats (samples are in nanoseconds). */
    uint64_t *sorted = malloc(n * sizeof(uint64_t));
    memcpy(sorted, samples, n * sizeof(uint64_t));
    qsort(sorted, n, sizeof(uint64_t), cmp_u64);

    uint64_t wall_ns = (uint64_t)(t_end.tv_sec - t_start.tv_sec) * 1000000000ULL +
                       (uint64_t)(t_end.tv_nsec - t_start.tv_nsec);

    double min_us   = sorted[0]            / 1000.0;
    double p50_us   = pct(sorted, n, 0.50) / 1000.0;
    double p95_us   = pct(sorted, n, 0.95) / 1000.0;
    double p99_us   = pct(sorted, n, 0.99) / 1000.0;
    double max_us   = sorted[n-1]          / 1000.0;
    double tot_ms   = sum_ns / 1e6;                 /* == sum(samples), reconciles with percentiles */
    double mean_us  = (sum_ns / (double)n) / 1000.0; /* == mean(samples) */
    double wall_ms  = wall_ns / 1e6;                 /* diagnostic: true loop wall-clock, includes housekeeping */

    printf("N=%d  total=%.3f ms  per-rule mean=%.3f us  min=%.3f  p50=%.3f  p95=%.3f  p99=%.3f  max=%.3f  wall=%.3f\n",
           n, tot_ms, mean_us, min_us, p50_us, p95_us, p99_us, max_us, wall_ms);

    if (csv) {
        FILE *f = fopen(csv, "w");
        if (!f) { perror("fopen"); free(samples); free(sorted); return 1; }
        fprintf(f, "rule_index,update_us\n");
        for (int i = 0; i < n; i++)
            fprintf(f, "%d,%.3f\n", i, samples[i] / 1000.0);
        fclose(f);
    }

    free(samples);
    free(sorted);
    return 0;
}
