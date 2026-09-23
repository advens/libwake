/*
 * test_pheromone_tsan.c - 1 writer (deposit + decay) vs N readers (lookup)
 *
 * Build with -fsanitize=thread. The pheromone hot line is atomic; entity
 * identity is seqlock-protected. A data race the contract forbids fails.
 *
 * Copyright (c) 2026 Advens. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "wake_pheromone.h"
#include "wake_entity.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define N_READERS     4
#define N_ENTITIES    16
#define TARGET_READS  40000ul

static wake_pheromone_t *g_pt;
static _Atomic unsigned long g_reads;
static wake_entity_t g_ents[N_ENTITIES];

static void *
writer(void *arg)
{
    uint32_t round = 0;

    (void)arg;
    while (atomic_load_explicit(&g_reads, memory_order_relaxed) < TARGET_READS) {
        int ei = (int)(round % N_ENTITIES);

        round++;
        (void)wake_pheromone_deposit(g_pt, &g_ents[ei], 0, 0, 1, 50, 0);
        if (round % 64 == 63) {
            (void)wake_pheromone_decay(g_pt);
        }
    }
    return NULL;
}

static void *
reader(void *arg)
{
    (void)arg;
    while (atomic_load_explicit(&g_reads, memory_order_relaxed) < TARGET_READS) {
        int ei = (int)(atomic_fetch_add_explicit(&g_reads, 1,
                                                 memory_order_relaxed)
                       % N_ENTITIES);

        (void)wake_pheromone_lookup(g_pt, &g_ents[ei]);
    }
    return NULL;
}

int
main(void)
{
    char path[] = "/tmp/pht_tsan.XXXXXX";
    int fd;
    pthread_t w, r[N_READERS];
    wake_pheromone_config_t cfg;
    int i;

    fd = mkstemp(path);
    if (fd < 0) {
        perror("mkstemp");
        return 1;
    }
    close(fd);
    unlink(path);

    memset(&cfg, 0, sizeof(cfg));
    cfg.capacity = 256;
    g_pt = wake_pheromone_create(path, &cfg);
    if (g_pt == NULL) {
        perror("wake_pheromone_create");
        return 1;
    }
    for (i = 0; i < N_ENTITIES; i++) {
        wake_entity_init_ipv4(&g_ents[i], WAKE_EC_WHO,
                              0x0a000000u + (uint32_t)i);
    }

    pthread_create(&w, NULL, writer, NULL);
    for (i = 0; i < N_READERS; i++) {
        pthread_create(&r[i], NULL, reader, NULL);
    }
    pthread_join(w, NULL);
    for (i = 0; i < N_READERS; i++) {
        pthread_join(r[i], NULL);
    }
    wake_pheromone_close(g_pt);
    unlink(path);
    printf("test_pheromone_tsan: 1 writer vs %d readers, ~%lu reads\n",
           N_READERS, (unsigned long)atomic_load(&g_reads));
    return 0;
}
