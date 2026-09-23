/*
 * fuzz_tac.c - libFuzzer: crafted TAC mmap plus a byte-driven op stream.
 *
 * Data[0] & 1 == 0: open the bytes as a table file (fail closed).
 * Data[0] & 1 == 1: create a tiny table and drive
 * reinforce / batch / query / route / decay / reset / iterate / stats
 * from the rest. Must not crash, leak maps, or insert uncapped.
 *
 * libFuzzer smoke on untrusted byte surfaces. Bounded in
 * Makefile.port libfuzz-ci (-max_total_time=15).
 *
 * Copyright (c) 2026 Advens. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "wake_tac.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static bool
iter_keep(const wake_tac_entry_t *entry, void *ctx)
{
    uint32_t *n = ctx;

    (void)entry;
    if (n != NULL) {
        (*n)++;
    }
    return true;
}

static void
fill_acts(const uint8_t *p, size_t left, wake_tac_activation_t *acts,
          uint32_t *nacts, uint32_t max)
{
    uint32_t n = 0;

    while (n < max && left >= 8) {
        uint32_t tech;
        uint16_t eta, src;

        memcpy(&tech, p, 4);
        memcpy(&eta, p + 4, 2);
        memcpy(&src, p + 6, 2);
        p += 8;
        left -= 8;
        acts[n].technique = tech;
        acts[n].eta_fp16 = eta;
        acts[n].source_id = src; /* 0 and 0xFFFF are real sentinels */
        n++;
    }
    *nacts = n;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char path[] = "/tmp/wakefuzz_tac.XXXXXX";
    int fd;
    wake_tac_t *t;
    ssize_t w;

    if (size == 0) {
        return 0;
    }
    fd = mkstemp(path);
    if (fd < 0) {
        return 0;
    }

    if ((data[0] & 1u) == 0) {
        size_t n = size > (1u << 20) ? (1u << 20) : size;
        wake_tac_stats_t st;
        wake_tac_entry_t ent;
        uint32_t visited = 0;

        w = write(fd, data, n);
        (void)w;
        close(fd);
        t = wake_tac_open(path);
        if (t != NULL) {
            wake_tac_snapshot_t snap;
            uint8_t key[8];

            memset(key, 0x41, sizeof(key));
            (void)wake_tac_query(t, key, sizeof(key), &snap);
            wake_tac_stats(t, &st);
            (void)wake_tac_iterate(t, iter_keep, &visited);
            (void)wake_tac_read_entry(t, 0, &ent);
            (void)st;
            (void)ent;
            wake_tac_close(t);
        }
        unlink(path);
        return 0;
    }

    close(fd);
    unlink(path);
    {
        wake_tac_config_t cfg;
        wake_tac_activation_t acts[8];
        wake_tac_snapshot_t snap;
        wake_tac_input_t routed[8];
        wake_tac_stats_t st;
        wake_tac_entry_t ent;
        uint8_t keys[4][16];
        uint32_t nacts, now, ops, i;
        const uint8_t *p;
        size_t left;
        uint8_t ksel;

        memset(&cfg, 0, sizeof(cfg));
        cfg.capacity = 64;
        cfg.occ_slots = 64;
        cfg.per_entity_cap = 8;
        t = wake_tac_create(path, &cfg);
        if (t == NULL) {
            return 0;
        }

        p = data + 1;
        left = size - 1;
        memset(keys, 0, sizeof(keys));
        for (i = 0; i < 4; i++) {
            if (left >= 16) {
                memcpy(keys[i], p, 16);
                p += 16;
                left -= 16;
            }
        }
        now = 1;
        ops = 0;
        while (left > 0 && ops < 48) {
            uint8_t op = p[0] & 7u;
            const uint8_t *key;
            size_t klen;

            p++;
            left--;
            ops++;
            ksel = (left > 0) ? (p[0] & 3u) : 0;
            key = keys[ksel];
            klen = sizeof(keys[0]);
            switch (op) {
            case 0: /* reinforce one pair */
                if (left < 14) {
                    break;
                }
                {
                    uint32_t ta, tb;
                    uint16_t eta, src;

                    memcpy(&ta, p, 4);
                    memcpy(&tb, p + 4, 4);
                    memcpy(&eta, p + 8, 2);
                    memcpy(&src, p + 10, 2);
                    memcpy(&now, p + 12, 2);
                    p += 14;
                    left -= 14;
                    (void)wake_tac_reinforce(t, key, klen, ta, tb, eta, src,
                                             now);
                }
                break;
            case 1: /* reinforce_batch */
                fill_acts(p, left, acts, &nacts, 8);
                if (nacts * 8u <= left) {
                    p += nacts * 8u;
                    left -= nacts * 8u;
                }
                (void)wake_tac_reinforce_batch(t, key, klen, acts, nacts, now);
                break;
            case 2: /* query, including empty key */
                if ((ops & 1u) != 0) {
                    (void)wake_tac_query(t, key, 0, &snap);
                }
                (void)wake_tac_query(t, key, klen, &snap);
                break;
            case 3: /* route */
                fill_acts(p, left, acts, &nacts, 8);
                if (nacts * 8u <= left) {
                    p += nacts * 8u;
                    left -= nacts * 8u;
                }
                (void)wake_tac_route(t, key, klen, acts, nacts, routed, 8);
                break;
            case 4: /* decay */
                (void)wake_tac_decay(t);
                now++;
                break;
            case 5: /* reset (flip tool; must stay discardable) */
                wake_tac_reset(t);
                break;
            case 6: /* stats / iterate / read_entry */
                {
                    uint32_t visited = 0;
                    uint32_t slot = 0;

                    wake_tac_stats(t, &st);
                    (void)wake_tac_iterate(t, iter_keep, &visited);
                    if (left >= 1) {
                        slot = p[0];
                        p++;
                        left--;
                    }
                    (void)wake_tac_read_entry(t, slot, &ent);
                    (void)st;
                    (void)ent;
                    (void)visited;
                }
                break;
            default: /* pack + now */
                {
                    uint16_t base = 1071;
                    uint8_t sub = 1;
                    char lab[16];
                    size_t llen;

                    if (left >= 3) {
                        memcpy(&base, p, 2);
                        sub = p[2];
                        p += 3;
                        left -= 3;
                    }
                    (void)wake_tac_pack(base, sub);
                    llen = left > 8 ? 8 : left;
                    memset(lab, 0, sizeof(lab));
                    if (llen > 0) {
                        memcpy(lab, p, llen);
                        p += llen;
                        left -= llen;
                    }
                    (void)wake_tac_pack_label(lab, llen);
                    (void)wake_tac_now(t);
                }
                break;
            }
        }
        wake_tac_close(t);
        unlink(path);
    }
    return 0;
}
