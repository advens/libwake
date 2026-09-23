/*
 * test_swim.c: wake_swim protocol + Local Health Multiplier tests
 *
 * Synthetic time only (now_ms passed explicitly everywhere), no real
 * network, no real clock; matches wake_swim.h's own "no internal clocks"
 * design. One process, one wake_swim_t per case.
 *
 * Copyright (c) 2026 Advens. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "wake_swim.h"

#include <stdio.h>
#include <string.h>

static int g_fail;

#define CHECK(cond)                                                           \
    do {                                                                      \
        if (!(cond)) {                                                        \
            printf("  FAIL %s:%d  %s\n", __func__, __LINE__, #cond);          \
            g_fail = 1;                                                       \
            return 1;                                                         \
        }                                                                     \
    } while (0)

static void
mk_id(uint8_t out[WAKE_SWIM_NODE_ID_LEN], uint8_t fill)
{
    memset(out, fill, WAKE_SWIM_NODE_ID_LEN);
}

/* -------------------------------------------------------------------------- */

/* Lifecycle: create with defaults, self is not a member, destroy is safe. */
static int test_lifecycle(void)
{
    uint8_t self[WAKE_SWIM_NODE_ID_LEN];
    mk_id(self, 0x01);

    wake_swim_t *sw = wake_swim_create(self, 0x7f000001u, 7946, NULL);
    CHECK(sw);
    CHECK(wake_swim_health(sw) == 0);

    wake_swim_stats_t st;
    wake_swim_stats(sw, &st);
    CHECK(st.total == 0);

    wake_swim_destroy(sw);
    return 0;
}

/* Add/find/remove round-trips correctly, and self cannot be added. */
static int test_member_lifecycle(void)
{
    uint8_t self[WAKE_SWIM_NODE_ID_LEN], peer[WAKE_SWIM_NODE_ID_LEN];
    mk_id(self, 0x01);
    mk_id(peer, 0x02);

    wake_swim_t *sw = wake_swim_create(self, 0x7f000001u, 7946, NULL);
    CHECK(sw);

    CHECK(wake_swim_add_member(sw, peer, 0x7f000002u, 7946, 1000) == WAKE_SWIM_OK);
    CHECK(wake_swim_add_member(sw, self, 0x7f000001u, 7946, 1000) == WAKE_SWIM_SELF);

    const wake_swim_member_t *m = wake_swim_find(sw, peer);
    CHECK(m);
    CHECK(m->state == WAKE_SWIM_ALIVE);

    CHECK(wake_swim_suspect_member(sw, peer, 2000) == WAKE_SWIM_OK);
    m = wake_swim_find(sw, peer);
    CHECK(m->state == WAKE_SWIM_SUSPECT);

    wake_swim_destroy(sw);
    return 0;
}

/* Baseline (health=0) suspicion timeout matches the documented formula
 * exactly: suspicion_mult * log2(max(2, alive_count)) * protocol_period_ms.
 * This is the regression anchor: if this ever drifts, every test below that
 * compares AGAINST a multiple of this value silently stops meaning anything. */
static int test_suspect_timeout_baseline(void)
{
    uint8_t self[WAKE_SWIM_NODE_ID_LEN];
    mk_id(self, 0x01);

    wake_swim_config_t cfg = wake_swim_default_config();
    cfg.suspicion_mult = 5;
    cfg.protocol_period_ms = 1000;
    cfg.suspect_timeout_ms = 0; /* force auto formula */

    wake_swim_t *sw = wake_swim_create(self, 0x7f000001u, 7946, &cfg);
    CHECK(sw);

    /* alive_count starts at 0 -> formula clamps n to 2, log2(2) = 1 */
    CHECK(wake_swim_suspect_timeout(sw) == 5u * 1u * 1000u);

    wake_swim_destroy(sw);
    return 0;
}

/* Reporting degraded health widens the timeout by exactly (1 + health_score),
 * and the timeout is monotonic non-decreasing as health gets worse. */
static int test_health_widens_timeout(void)
{
    uint8_t self[WAKE_SWIM_NODE_ID_LEN];
    mk_id(self, 0x01);

    wake_swim_config_t cfg = wake_swim_default_config();
    cfg.suspicion_mult = 5;
    cfg.protocol_period_ms = 1000;

    wake_swim_t *sw = wake_swim_create(self, 0x7f000001u, 7946, &cfg);
    CHECK(sw);

    uint32_t baseline = wake_swim_suspect_timeout(sw);
    CHECK(wake_swim_health(sw) == 0);

    uint32_t prev = baseline;
    for (int i = 1; i <= (int)WAKE_SWIM_HEALTH_MAX; i++) {
        wake_swim_report_health(sw, +1);
        CHECK(wake_swim_health(sw) == (uint32_t)i);
        uint32_t t = wake_swim_suspect_timeout(sw);
        CHECK(t == baseline * (uint32_t)(1 + i));
        CHECK(t > prev);
        prev = t;
    }

    wake_swim_destroy(sw);
    return 0;
}

/* Health cannot exceed WAKE_SWIM_HEALTH_MAX (bounded, per the Lifeguard
 * paper's own bound) and cannot go below 0 (never faster than baseline). */
static int test_health_clamps(void)
{
    uint8_t self[WAKE_SWIM_NODE_ID_LEN];
    mk_id(self, 0x01);

    wake_swim_t *sw = wake_swim_create(self, 0x7f000001u, 7946, NULL);
    CHECK(sw);

    for (int i = 0; i < 100; i++)
        wake_swim_report_health(sw, +1);
    CHECK(wake_swim_health(sw) == WAKE_SWIM_HEALTH_MAX);

    for (int i = 0; i < 100; i++)
        wake_swim_report_health(sw, -1);
    CHECK(wake_swim_health(sw) == 0);

    /* A single large negative delta also clamps at 0, not underflow. */
    wake_swim_report_health(sw, -1000);
    CHECK(wake_swim_health(sw) == 0);

    wake_swim_destroy(sw);
    return 0;
}

/* Health recovers (decreases) on good ticks, exercising both directions in
 * the same run rather than only ever increasing or only ever decreasing. */
static int test_health_recovers(void)
{
    uint8_t self[WAKE_SWIM_NODE_ID_LEN];
    mk_id(self, 0x01);

    wake_swim_t *sw = wake_swim_create(self, 0x7f000001u, 7946, NULL);
    CHECK(sw);

    wake_swim_report_health(sw, +1);
    wake_swim_report_health(sw, +1);
    wake_swim_report_health(sw, +1);
    CHECK(wake_swim_health(sw) == 3);

    wake_swim_report_health(sw, -1);
    CHECK(wake_swim_health(sw) == 2);

    wake_swim_destroy(sw);
    return 0;
}

/* wake_swim_reset() zeroes health_score along with the other lifetime
 * counters it already resets; a stale health score surviving a reset would
 * silently mis-time every suspicion decision made right after. */
static int test_reset_clears_health(void)
{
    uint8_t self[WAKE_SWIM_NODE_ID_LEN];
    mk_id(self, 0x01);

    wake_swim_t *sw = wake_swim_create(self, 0x7f000001u, 7946, NULL);
    CHECK(sw);

    wake_swim_report_health(sw, +5);
    CHECK(wake_swim_health(sw) == 5);

    wake_swim_reset(sw);
    CHECK(wake_swim_health(sw) == 0);

    wake_swim_destroy(sw);
    return 0;
}

/* An operator-fixed suspect_timeout_ms is still scaled by health: the
 * Lifeguard rationale (don't trust my own timing under load) applies
 * whether the base timeout came from the formula or an explicit override. */
static int test_health_scales_fixed_timeout_too(void)
{
    uint8_t self[WAKE_SWIM_NODE_ID_LEN];
    mk_id(self, 0x01);

    wake_swim_config_t cfg = wake_swim_default_config();
    cfg.suspect_timeout_ms = 10000; /* explicit override */

    wake_swim_t *sw = wake_swim_create(self, 0x7f000001u, 7946, &cfg);
    CHECK(sw);
    CHECK(wake_swim_suspect_timeout(sw) == 10000);

    wake_swim_report_health(sw, +1);
    CHECK(wake_swim_suspect_timeout(sw) == 20000);

    wake_swim_destroy(sw);
    return 0;
}

/* A large protocol period must saturate the timeout, never wrap it to a small one
 * (a wrapped timeout would make peers look dead almost immediately). */
static int test_timeout_saturates(void)
{
    uint8_t self[WAKE_SWIM_NODE_ID_LEN];
    mk_id(self, 0x01);

    wake_swim_config_t cfg = wake_swim_default_config();
    cfg.suspicion_mult = 5;
    cfg.protocol_period_ms = UINT32_MAX / 2;
    cfg.suspect_timeout_ms = 0;

    wake_swim_t *sw = wake_swim_create(self, 0x7f000001u, 7946, &cfg);
    CHECK(sw);
    CHECK(wake_swim_suspect_timeout(sw) == UINT32_MAX);

    wake_swim_destroy(sw);
    return 0;
}

/* -------------------------------------------------------------------------- */

int main(void)
{
    struct {
        const char *name;
        int (*fn)(void);
    } cases[] = {
        {"lifecycle", test_lifecycle},
        {"member_lifecycle", test_member_lifecycle},
        {"suspect_timeout_baseline", test_suspect_timeout_baseline},
        {"health_widens_timeout", test_health_widens_timeout},
        {"health_clamps", test_health_clamps},
        {"health_recovers", test_health_recovers},
        {"reset_clears_health", test_reset_clears_health},
        {"health_scales_fixed_timeout_too", test_health_scales_fixed_timeout_too},
        {"timeout_saturates", test_timeout_saturates},
    };
    int n = (int)(sizeof(cases) / sizeof(cases[0]));
    int passed = 0;
    for (int i = 0; i < n; i++) {
        int r = cases[i].fn();
        if (r == 0) {
            printf("  ok   %s\n", cases[i].name);
            passed++;
        }
    }
    printf("test_swim: %d/%d passed\n", passed, n);
    return g_fail ? 1 : 0;
}
