/*
 * fuzz_swim.c - libFuzzer: untrusted SWIM update applied to a tiny table.
 *
 * The host application copies UDP payload into wake_swim_update_t. A liar can send any
 * 48-byte update. apply_update must not crash, overflow the member list,
 * or rewrite self's key.
 *
 * Copyright (c) 2026 Advens. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "wake_swim.h"

#include <stdint.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static const uint8_t self[WAKE_SWIM_NODE_ID_LEN] = {1};
    wake_swim_config_t cfg;
    wake_swim_t *sw;
    wake_swim_update_t upd;
    wake_swim_stats_t st;

    memset(&cfg, 0, sizeof(cfg));
    cfg.max_members = 16;
    cfg.update_queue_size = 16;
    cfg.suspicion_mult = 2;
    cfg.max_piggybacks = 2;
    cfg.protocol_period_ms = 1000;
    cfg.prng_seed = 1;

    sw = wake_swim_create(self, 0x0100007f, 7946, &cfg);
    if (sw == NULL) {
        return 0;
    }

    memset(&upd, 0, sizeof(upd));
    if (size > sizeof(upd)) {
        size = sizeof(upd);
    }
    if (size > 0) {
        memcpy(&upd, data, size);
    }
    (void)wake_swim_apply_update(sw, &upd, 1000);
    (void)wake_swim_check_suspects(sw, 5000);
    (void)wake_swim_reap(sw, 8000, 2000);
    wake_swim_stats(sw, &st);
    (void)st;
    wake_swim_destroy(sw);
    return 0;
}
