/*
 * test_tac_tsan.c: wake_tac concurrency harness (ThreadSanitizer gate)
 *
 * One writer thread runs the write path (reinforce, batch, decay). N reader
 * threads run the read path (query, route, iterate, stats) against the same
 * table. Build with -fsanitize=thread; any data race the contract forbids
 * fails the run.
 *
 * The contract under test (wake_tac.h): single writer, concurrent readers;
 * counters on cache line 0 are atomic; entity_hash is atomic; the 56-byte
 * ident copy is written under version and is not read concurrently;
 * readers skip weight == 0.
 *
 * Copyright (c) 2026 Advens. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "wake_tac.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define N_READERS      4
#define N_ENTITIES     16
/* The writer runs until the readers have collectively done this much work, so
 * the contended windows (slot reclaim vs read, entity_hash vs write,
 * sidecar rebuild vs scan) are actually exercised under contention rather than
 * the writer finishing first. */
#define TARGET_READS   40000ul

static wake_tac_t *g_tac;
static _Atomic int g_stop;
static _Atomic unsigned long g_reads;

static void
entity_key(char *buf, size_t cap, int i)
{
    snprintf(buf, cap, "10.0.%d.%d|user%d", i / 8, i % 8, i);
}

static void *
writer(void *arg)
{
    (void)arg;
    uint32_t round = 0;
    while (atomic_load_explicit(&g_reads, memory_order_relaxed) < TARGET_READS) {
        round++;
        int ei = (int)(round % N_ENTITIES);
        char key[48];
        entity_key(key, sizeof(key), ei);
        size_t klen = strlen(key);

        wake_tac_activation_t acts[4] = {
            {wake_tac_pack((uint16_t)(1000 + (round % 40)), 0),
             39321, (uint16_t)(1 + (round % 7))},
            {wake_tac_pack((uint16_t)(1100 + (round % 37)), 1),
             19661, (uint16_t)(1 + (round % 5))},
            {wake_tac_pack((uint16_t)(1200 + (round % 31)), 0),
             65535, (uint16_t)(1 + (round % 3))},
            {wake_tac_pack_label("suricata:et-scan", 16),
             6554, (uint16_t)(1 + (round % 11))},
        };
        wake_tac_reinforce_batch(g_tac, (const uint8_t *)key, klen, acts, 4,
                                 round);

        wake_tac_reinforce(g_tac, (const uint8_t *)key, klen,
                           acts[0].technique, acts[2].technique,
                           39321, (uint16_t)(20 + (round % 9)), round);

        if (round % 64 == 63)
            wake_tac_decay(g_tac);
    }
    return NULL;   /* main sets g_stop after joining the writer */
}

static bool
iter_cb(const wake_tac_entry_t *e, void *ctx)
{
    (void)ctx;
    /* touch the snapshot so the compiler cannot elide the read */
    volatile uint32_t w = e->weight;
    (void)w;
    return true;
}

static void *
reader(void *arg)
{
    (void)arg;
    unsigned long n = 0;
    while (!atomic_load_explicit(&g_stop, memory_order_acquire)) {
        char key[48];
        entity_key(key, sizeof(key), (int)(n % N_ENTITIES));
        size_t klen = strlen(key);

        wake_tac_snapshot_t s;
        if (wake_tac_query(g_tac, (const uint8_t *)key, klen, &s)) {
            volatile uint32_t m = s.coupling_mass;
            (void)m;
        }

        wake_tac_activation_t acts[3] = {
            {wake_tac_pack(1000, 0), 39321, 1},
            {wake_tac_pack(1100, 1), 19661, 2},
            {wake_tac_pack(1200, 0), 65535, 3},
        };
        wake_tac_input_t out[3];
        wake_tac_route(g_tac, (const uint8_t *)key, klen, acts, 3, out, 3);

        /* Every reader exercises iterate and the stats scan; this is the
         * concurrent counterpart of the writer's slot reclaim. */
        if ((n & 15) == 0) {
            wake_tac_stats_t st;
            wake_tac_stats(g_tac, &st);
            wake_tac_iterate(g_tac, iter_cb, NULL);
        }
        n++;
        if ((n & 1023) == 0)
            atomic_fetch_add_explicit(&g_reads, 1024, memory_order_relaxed);
    }
    atomic_fetch_add_explicit(&g_reads, n & 1023, memory_order_relaxed);
    return NULL;
}

int
main(void)
{
    wake_tac_config_t cfg = {0};
    cfg.capacity = 1024;    /* small: the reader scans are O(capacity) */
    cfg.occ_slots = 1024;   /* must be >= capacity */
    cfg.per_entity_cap = 16;
    cfg.corroboration_src_min = 2;
    cfg.budget_per_source = 60000;

    g_tac = wake_tac_create("/tmp/tac_tsan.dat", &cfg);
    if (!g_tac) {
        perror("wake_tac_create");
        return 1;
    }

    pthread_t wt;
    pthread_t rt[N_READERS];

    if (pthread_create(&wt, NULL, writer, NULL) != 0)
        return 1;
    for (int i = 0; i < N_READERS; i++)
        if (pthread_create(&rt[i], NULL, reader, NULL) != 0)
            return 1;

    pthread_join(wt, NULL);
    atomic_store_explicit(&g_stop, 1, memory_order_release);
    for (int i = 0; i < N_READERS; i++)
        pthread_join(rt[i], NULL);

    wake_tac_stats_t st;
    wake_tac_stats(g_tac, &st);
    printf("test_tac_tsan: 1 writer vs %d readers, ~%lu reads\n",
           N_READERS, atomic_load_explicit(&g_reads, memory_order_relaxed));
    printf("  occupied=%u tombstones=%u at_cap=%u quarantined=%u\n",
           st.occupied, st.tombstones, st.entities_at_cap, st.quarantined);
    printf("  PASS (no sanitizer report)\n");

    wake_tac_close(g_tac);
    return 0;
}
