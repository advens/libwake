/*
 * test_quorum.c: wake_quorum threshold and sweep tests
 *
 * Exercises the evaluator against a real wake_pheromone_t table (not a
 * mock): the sweep reads live confidence/hit_count/src_count through the
 * same seqlock path immesh uses. One process, one table file per case.
 *
 * Copyright (c) 2026 Advens. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "wake_quorum.h"

#include <stdio.h>
#include <string.h>

static int g_fail;

#define CHECK(cond)                                                          \
    do {                                                                     \
        if (!(cond)) {                                                       \
            printf("  FAIL %s:%d  %s\n", __func__, __LINE__, #cond);         \
            g_fail = 1;                                                      \
            return 1;                                                        \
        }                                                                    \
    } while (0)

static wake_pheromone_t *
mk_pht(const char *name, uint32_t capacity)
{
    char path[256];
    snprintf(path, sizeof(path), "/tmp/quorum_test_%s.dat", name);
    wake_pheromone_config_t cfg = {0};
    cfg.capacity = capacity;
    return wake_pheromone_create(path, &cfg);
}

static void
mk_entity(wake_entity_t *e, uint8_t fill)
{
    uint32_t addr = 0x01000000u | fill;
    wake_entity_init_ipv4(e, WAKE_EC_WHO, addr);
}

/* -------------------------------------------------------------------------- */
/* Configuration and pure functions                                          */
/* -------------------------------------------------------------------------- */

static int test_default_config_matches_docs(void)
{
    wake_quorum_config_t cfg = wake_quorum_default_config();
    CHECK(cfg.observe_confidence == 5000);
    CHECK(cfg.observe_min_hits == 3);
    CHECK(cfg.alert_confidence == 20000);
    CHECK(cfg.alert_min_sources == 2);
    CHECK(cfg.alert_min_hits == 5);
    CHECK(cfg.retract_confidence == 2000);
    return 0;
}

static int test_classify_boundaries(void)
{
    wake_quorum_config_t cfg = wake_quorum_default_config();

    CHECK(wake_quorum_classify(&cfg, 0, 0, 0) == WAKE_QUORUM_NONE);
    CHECK(wake_quorum_classify(&cfg, 4999, 1, 3) == WAKE_QUORUM_NONE); /* confidence short */
    CHECK(wake_quorum_classify(&cfg, 5000, 1, 2) == WAKE_QUORUM_NONE); /* hits short */
    CHECK(wake_quorum_classify(&cfg, 5000, 1, 3) == WAKE_QUORUM_OBSERVE); /* exact threshold */
    CHECK(wake_quorum_classify(&cfg, 19999, 2, 5) == WAKE_QUORUM_OBSERVE); /* confidence short of alert */
    CHECK(wake_quorum_classify(&cfg, 20000, 1, 5) == WAKE_QUORUM_OBSERVE); /* sources short */
    CHECK(wake_quorum_classify(&cfg, 20000, 2, 4) == WAKE_QUORUM_OBSERVE); /* hits short */
    CHECK(wake_quorum_classify(&cfg, 20000, 2, 5) == WAKE_QUORUM_ALERT); /* exact threshold */
    CHECK(wake_quorum_classify(&cfg, 100000, 10, 100) == WAKE_QUORUM_ALERT);
    return 0;
}

static int test_check_inline_is_conservative_overestimate(void)
{
    wake_quorum_config_t cfg = wake_quorum_default_config();
    /* Confidence alone crosses observe_confidence: true even with zero hits,
     * because check_inline exists to schedule a sweep, not to decide alone. */
    CHECK(wake_quorum_check_inline(&cfg, 5000) == true);
    CHECK(wake_quorum_check_inline(&cfg, 4999) == false);
    CHECK(wake_quorum_check_inline(&cfg, 0) == false);
    return 0;
}

static int test_lifecycle_create_destroy(void)
{
    wake_quorum_t *q = wake_quorum_create(64, NULL);
    CHECK(q);
    CHECK(q->capacity == 64);
    CHECK(q->config.observe_confidence == 5000); /* NULL cfg -> defaults */
    CHECK(q->observations_emitted == 0);
    wake_quorum_destroy(q);
    wake_quorum_destroy(NULL); /* must not crash */
    return 0;
}

/* -------------------------------------------------------------------------- */
/* Sweep against a real pheromone table                                      */
/* -------------------------------------------------------------------------- */

/* Collect every hit emitted by a plain (non-collect) sweep via a callback,
 * so the callback-based API gets real coverage alongside sweep_collect. */
struct emit_log {
    wake_quorum_action_t actions[16];
    int n;
};

static bool
log_emit(wake_quorum_action_t action, uint32_t slot_idx,
         const wake_pheromone_entry_t *entry, void *ctx)
{
    (void)slot_idx;
    (void)entry;
    struct emit_log *log = ctx;
    if (log->n < 16)
        log->actions[log->n++] = action;
    return true;
}

static int test_sweep_emits_observe_then_alert_then_suppressed(void)
{
    wake_pheromone_t *pt = mk_pht("lifecycle", 64);
    CHECK(pt);
    wake_quorum_t *q = wake_quorum_create(64, NULL);
    CHECK(q);

    wake_entity_t e;
    mk_entity(&e, 1);

    /* Three local deposits: confidence 6000, hits 3, src 1. Crosses OBSERVE
     * (>=5000 confidence, >=3 hits) but not ALERT (needs >=20000 and 2 sources). */
    for (int i = 0; i < 3; i++)
        wake_pheromone_deposit(pt, &e, WAKE_ACTION_AUTH, WAKE_OUTCOME_FAILURE, 1, 2000, 0);

    struct emit_log log = {0};
    wake_quorum_sweep_result_t r = wake_quorum_sweep(q, pt, log_emit, &log);
    CHECK(r.slots_scanned == 64);
    CHECK(r.slots_live == 1);
    CHECK(r.new_observations == 1);
    CHECK(r.new_alerts == 0);
    CHECK(q->observations_emitted == 1);
    CHECK(log.n == 1 && log.actions[0] == WAKE_QUORUM_ACT_OBSERVE);

    /* Same state, second sweep: suppressed, not re-emitted. */
    r = wake_quorum_sweep(q, pt, NULL, NULL);
    CHECK(r.new_observations == 0);
    CHECK(r.suppressed == 1);
    CHECK(q->observations_emitted == 1);

    /* Reinforce once (src_count -> 2): confidence 14000, hits 4. Still short
     * of ALERT's 20000 confidence, so classify still returns OBSERVE and the
     * sweep suppresses (same tier already emitted), not a fresh OBSERVE. */
    wake_pheromone_reinforce(pt, &e, WAKE_ACTION_AUTH, WAKE_OUTCOME_FAILURE, 1, 8000, 0);
    r = wake_quorum_sweep(q, pt, NULL, NULL);
    CHECK(r.new_observations == 0 && r.new_alerts == 0);
    CHECK(r.suppressed == 1);

    /* Reinforce again (src_count -> 3): confidence 22000, hits 5. Crosses
     * ALERT (>=20000, >=2 sources, >=5 hits). */
    wake_pheromone_reinforce(pt, &e, WAKE_ACTION_AUTH, WAKE_OUTCOME_FAILURE, 1, 8000, 0);
    log.n = 0;
    r = wake_quorum_sweep(q, pt, log_emit, &log);
    CHECK(r.new_alerts == 1);
    CHECK(r.new_observations == 0); /* ALERT implies OBSERVE: only the highest tier fires */
    CHECK(q->alerts_emitted == 1);
    CHECK(log.n == 1 && log.actions[0] == WAKE_QUORUM_ACT_ALERT);

    /* Unchanged: suppressed again. */
    r = wake_quorum_sweep(q, pt, NULL, NULL);
    CHECK(r.suppressed == 1);

    wake_quorum_destroy(q);
    wake_pheromone_close(pt);
    return 0;
}

static int test_sweep_retract_when_still_live_and_decayed(void)
{
    wake_pheromone_t *pt = mk_pht("retract", 64);
    CHECK(pt);
    wake_quorum_t *q = wake_quorum_create(64, NULL);
    CHECK(q);

    wake_entity_t e;
    mk_entity(&e, 2);

    /* Reach ALERT directly: one deposit (src=1) + one reinforce (src=2),
     * hits=2 short of alert_min_hits=5, so pad with three plain deposits. */
    wake_pheromone_deposit(pt, &e, WAKE_ACTION_NETWORK, WAKE_OUTCOME_SUCCESS, 1, 11000, 0);
    wake_pheromone_reinforce(pt, &e, WAKE_ACTION_NETWORK, WAKE_OUTCOME_SUCCESS, 1, 11000, 0);
    wake_pheromone_deposit(pt, &e, WAKE_ACTION_NETWORK, WAKE_OUTCOME_SUCCESS, 1, 0, 0);
    wake_pheromone_deposit(pt, &e, WAKE_ACTION_NETWORK, WAKE_OUTCOME_SUCCESS, 1, 0, 0);
    wake_pheromone_deposit(pt, &e, WAKE_ACTION_NETWORK, WAKE_OUTCOME_SUCCESS, 1, 0, 0);
    CHECK(wake_pheromone_lookup(pt, &e) == 22000);

    wake_quorum_sweep_result_t r = wake_quorum_sweep(q, pt, NULL, NULL);
    CHECK(r.new_alerts == 1);

    /* Decay 47 cycles: default 0.95/cycle takes 22000 to ~1974, below
     * retract_confidence (2000) but well above noise_floor (100), so the
     * entry stays live. Verified offline: 46 cycles leaves it >= 2000. */
    for (int i = 0; i < 47; i++)
        wake_pheromone_decay(pt);
    uint32_t conf = wake_pheromone_lookup(pt, &e);
    CHECK(conf > 0 && conf < 2000);

    struct emit_log log = {0};
    r = wake_quorum_sweep(q, pt, log_emit, &log);
    CHECK(r.new_retractions == 1);
    CHECK(q->retractions_emitted == 1);
    CHECK(log.n == 1 && log.actions[0] == WAKE_QUORUM_ACT_RETRACT);

    /* Retract resets emitted_tier to NONE: a fresh rise back to OBSERVE
     * emits again instead of staying suppressed at a stale ALERT tier. */
    wake_pheromone_reinforce(pt, &e, WAKE_ACTION_NETWORK, WAKE_OUTCOME_SUCCESS, 1, 6000, 0);
    r = wake_quorum_sweep(q, pt, NULL, NULL);
    CHECK(r.new_observations == 1);

    wake_quorum_destroy(q);
    wake_pheromone_close(pt);
    return 0;
}

static int test_sweep_eviction_emits_no_retract(void)
{
    wake_pheromone_t *pt = mk_pht("eviction", 64);
    CHECK(pt);
    wake_quorum_t *q = wake_quorum_create(64, NULL);
    CHECK(q);

    wake_entity_t e;
    mk_entity(&e, 3);
    wake_pheromone_deposit(pt, &e, WAKE_ACTION_EXEC, WAKE_OUTCOME_SUCCESS, 1, 11000, 0);
    wake_pheromone_reinforce(pt, &e, WAKE_ACTION_EXEC, WAKE_OUTCOME_SUCCESS, 1, 11000, 0);
    wake_pheromone_deposit(pt, &e, WAKE_ACTION_EXEC, WAKE_OUTCOME_SUCCESS, 1, 0, 0);
    wake_pheromone_deposit(pt, &e, WAKE_ACTION_EXEC, WAKE_OUTCOME_SUCCESS, 1, 0, 0);
    wake_pheromone_deposit(pt, &e, WAKE_ACTION_EXEC, WAKE_OUTCOME_SUCCESS, 1, 0, 0);

    wake_quorum_sweep_result_t r = wake_quorum_sweep(q, pt, NULL, NULL);
    CHECK(r.new_alerts == 1);

    /* Remove outright (tombstone), rather than decaying past noise_floor:
     * same "entity data is gone" state, reached deterministically. */
    CHECK(wake_pheromone_remove(pt, &e));
    CHECK(wake_pheromone_lookup(pt, &e) == 0);

    r = wake_quorum_sweep(q, pt, NULL, NULL);
    CHECK(r.new_retractions == 0); /* eviction emits nothing, per contract */
    CHECK(r.slots_live == 0);
    CHECK(q->retractions_emitted == 0);

    wake_quorum_destroy(q);
    wake_pheromone_close(pt);
    return 0;
}

static int test_preseed_prevents_replay(void)
{
    const char *path = "/tmp/quorum_test_preseed.dat";
    wake_pheromone_config_t pcfg = {0};
    pcfg.capacity = 64;
    wake_pheromone_t *pt = wake_pheromone_create(path, &pcfg);
    CHECK(pt);

    wake_entity_t e;
    mk_entity(&e, 4);
    for (int i = 0; i < 3; i++)
        wake_pheromone_deposit(pt, &e, WAKE_ACTION_AUTH, WAKE_OUTCOME_FAILURE, 1, 2000, 0);
    /* Entity is already at OBSERVE tier (6000/3) before any evaluator exists,
     * as if reopening a persisted table after a restart. */

    wake_quorum_t *q = wake_quorum_create(64, NULL);
    CHECK(q);
    wake_quorum_preseed(q, pt);
    CHECK(q->observations_emitted == 0); /* preseed is not real emission */

    wake_quorum_sweep_result_t r = wake_quorum_sweep(q, pt, NULL, NULL);
    CHECK(r.new_observations == 0); /* not re-emitted: preseed already saw it */
    CHECK(r.suppressed == 1);

    wake_quorum_destroy(q);
    wake_pheromone_close(pt);
    return 0;
}

static int test_preseed_null_args_do_not_crash(void)
{
    wake_quorum_preseed(NULL, NULL);
    wake_quorum_t *q = wake_quorum_create(4, NULL);
    wake_quorum_preseed(q, NULL);
    wake_quorum_preseed(NULL, (wake_pheromone_t *)1);
    wake_quorum_destroy(q);
    return 0;
}

static int test_sweep_collect_matches_callback_sweep(void)
{
    wake_pheromone_t *pt_cb = mk_pht("collect_cb", 64);
    wake_pheromone_t *pt_co = mk_pht("collect_co", 64);
    CHECK(pt_cb && pt_co);
    wake_quorum_t *q_cb = wake_quorum_create(64, NULL);
    wake_quorum_t *q_co = wake_quorum_create(64, NULL);
    CHECK(q_cb && q_co);

    wake_entity_t e;
    mk_entity(&e, 5);
    for (int i = 0; i < 3; i++) {
        wake_pheromone_deposit(pt_cb, &e, WAKE_ACTION_DNS, WAKE_OUTCOME_SUCCESS, 1, 2000, 0);
        wake_pheromone_deposit(pt_co, &e, WAKE_ACTION_DNS, WAKE_OUTCOME_SUCCESS, 1, 2000, 0);
    }

    struct emit_log log = {0};
    wake_quorum_sweep_result_t r_cb = wake_quorum_sweep(q_cb, pt_cb, log_emit, &log);

    wake_quorum_hit_t hits[16];
    uint32_t hits_count = 0;
    wake_quorum_sweep_result_t r_co =
        wake_quorum_sweep_collect(q_co, pt_co, hits, 16, &hits_count);

    CHECK(r_cb.new_observations == r_co.new_observations);
    CHECK(r_cb.slots_live == r_co.slots_live);
    CHECK(log.n == (int)hits_count);
    CHECK(hits_count == 1 && hits[0].action == WAKE_QUORUM_ACT_OBSERVE);
    CHECK(wake_entity_eq(&hits[0].entry.entity, &e));

    wake_quorum_destroy(q_cb);
    wake_quorum_destroy(q_co);
    wake_pheromone_close(pt_cb);
    wake_pheromone_close(pt_co);
    return 0;
}

static int test_sweep_collect_caps_at_hits_capacity(void)
{
    wake_pheromone_t *pt = mk_pht("collect_cap", 64);
    CHECK(pt);
    wake_quorum_t *q = wake_quorum_create(64, NULL);
    CHECK(q);

    /* Five distinct entities all cross OBSERVE in one sweep. */
    for (uint8_t i = 0; i < 5; i++) {
        wake_entity_t e;
        mk_entity(&e, (uint8_t)(10 + i));
        for (int j = 0; j < 3; j++)
            wake_pheromone_deposit(pt, &e, WAKE_ACTION_FILE, WAKE_OUTCOME_SUCCESS, 1, 2000, 0);
    }

    wake_quorum_hit_t hits[2];
    uint32_t hits_count = 0;
    wake_quorum_sweep_result_t r = wake_quorum_sweep_collect(q, pt, hits, 2, &hits_count);

    /* All five are evaluated and counted... */
    CHECK(r.slots_live == 5);
    CHECK(r.new_observations == 5);
    CHECK(q->observations_emitted == 5);
    /* ...but only hits_capacity are actually written to the array. */
    CHECK(hits_count == 2);

    wake_quorum_destroy(q);
    wake_pheromone_close(pt);
    return 0;
}

static int test_sweep_null_args_return_zeroed_result(void)
{
    wake_quorum_sweep_result_t r = wake_quorum_sweep(NULL, NULL, NULL, NULL);
    CHECK(r.slots_scanned == 0 && r.new_observations == 0);

    uint32_t hits_count = 999;
    r = wake_quorum_sweep_collect(NULL, NULL, NULL, 0, &hits_count);
    CHECK(r.slots_scanned == 0);
    CHECK(hits_count == 0);
    return 0;
}

static int test_reset_clears_counters_and_emission_state(void)
{
    wake_pheromone_t *pt = mk_pht("reset", 64);
    CHECK(pt);
    wake_quorum_t *q = wake_quorum_create(64, NULL);
    CHECK(q);

    wake_entity_t e;
    mk_entity(&e, 6);
    for (int i = 0; i < 3; i++)
        wake_pheromone_deposit(pt, &e, WAKE_ACTION_AUTH, WAKE_OUTCOME_SUCCESS, 1, 2000, 0);
    wake_quorum_sweep(q, pt, NULL, NULL);
    CHECK(q->observations_emitted == 1);

    wake_quorum_reset(q);
    CHECK(q->observations_emitted == 0);
    CHECK(q->alerts_emitted == 0);
    CHECK(q->retractions_emitted == 0);
    CHECK(q->suppressed == 0);

    /* Emission state was cleared too: the same still-OBSERVE entity is
     * treated as a fresh crossing, not suppressed. */
    wake_quorum_sweep_result_t r = wake_quorum_sweep(q, pt, NULL, NULL);
    CHECK(r.new_observations == 1);

    wake_quorum_reset(NULL); /* must not crash */
    wake_quorum_destroy(q);
    wake_pheromone_close(pt);
    return 0;
}

static int test_capacity_is_bounded_by_the_smaller_table(void)
{
    wake_pheromone_t *pt = mk_pht("capmismatch", 64);
    CHECK(pt);
    wake_quorum_t *q = wake_quorum_create(16, NULL); /* smaller than pt */
    CHECK(q);

    wake_quorum_sweep_result_t r = wake_quorum_sweep(q, pt, NULL, NULL);
    CHECK(r.slots_scanned == 16);

    wake_quorum_destroy(q);
    wake_pheromone_close(pt);
    return 0;
}

/* -------------------------------------------------------------------------- */
/* Name accessors                                                            */
/* -------------------------------------------------------------------------- */

static int test_name_accessors_never_null(void)
{
    CHECK(strcmp(wake_quorum_tier_name(WAKE_QUORUM_NONE), "NONE") == 0);
    CHECK(strcmp(wake_quorum_tier_name(WAKE_QUORUM_OBSERVE), "OBSERVE") == 0);
    CHECK(strcmp(wake_quorum_tier_name(WAKE_QUORUM_ALERT), "ALERT") == 0);
    CHECK(strcmp(wake_quorum_tier_name((wake_quorum_tier_t)99), "UNKNOWN") == 0);

    CHECK(strcmp(wake_quorum_action_name(WAKE_QUORUM_ACT_NONE), "NONE") == 0);
    CHECK(strcmp(wake_quorum_action_name(WAKE_QUORUM_ACT_OBSERVE), "OBSERVE") == 0);
    CHECK(strcmp(wake_quorum_action_name(WAKE_QUORUM_ACT_ALERT), "ALERT") == 0);
    CHECK(strcmp(wake_quorum_action_name(WAKE_QUORUM_ACT_RETRACT), "RETRACT") == 0);
    CHECK(strcmp(wake_quorum_action_name((wake_quorum_action_t)99), "UNKNOWN") == 0);
    return 0;
}

int main(void)
{
    struct {
        const char *name;
        int (*fn)(void);
    } cases[] = {
        {"default_config_matches_docs", test_default_config_matches_docs},
        {"classify_boundaries", test_classify_boundaries},
        {"check_inline_is_conservative_overestimate", test_check_inline_is_conservative_overestimate},
        {"lifecycle_create_destroy", test_lifecycle_create_destroy},
        {"sweep_emits_observe_then_alert_then_suppressed", test_sweep_emits_observe_then_alert_then_suppressed},
        {"sweep_retract_when_still_live_and_decayed", test_sweep_retract_when_still_live_and_decayed},
        {"sweep_eviction_emits_no_retract", test_sweep_eviction_emits_no_retract},
        {"preseed_prevents_replay", test_preseed_prevents_replay},
        {"preseed_null_args_do_not_crash", test_preseed_null_args_do_not_crash},
        {"sweep_collect_matches_callback_sweep", test_sweep_collect_matches_callback_sweep},
        {"sweep_collect_caps_at_hits_capacity", test_sweep_collect_caps_at_hits_capacity},
        {"sweep_null_args_return_zeroed_result", test_sweep_null_args_return_zeroed_result},
        {"reset_clears_counters_and_emission_state", test_reset_clears_counters_and_emission_state},
        {"capacity_is_bounded_by_the_smaller_table", test_capacity_is_bounded_by_the_smaller_table},
        {"name_accessors_never_null", test_name_accessors_never_null},
    };
    int n = (int)(sizeof(cases) / sizeof(cases[0])), i, passed = 0;
    for (i = 0; i < n; i++)
        if (cases[i].fn() == 0) {
            printf("  ok   %s\n", cases[i].name);
            passed++;
        }
    printf("test_quorum: %d/%d passed\n", passed, n);
    return g_fail ? 1 : 0;
}
