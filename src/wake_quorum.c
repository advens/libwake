/*
 * wake_quorum.c: WAKE Quorum Evaluator implementation
 *
 * Threshold-based signal emission decisions. Scans the pheromone table
 * to detect entities crossing confidence thresholds, tracks per-slot
 * emission state to prevent duplicate signals.
 *
 * Copyright (c) 2026 Advens. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "wake_quorum.h"

#include <stdlib.h>
#include <string.h>

/* --------------------------------------------------------------------------
 * Default configuration
 * -------------------------------------------------------------------------- */

wake_quorum_config_t
wake_quorum_default_config(void)
{
    wake_quorum_config_t cfg = {
        .observe_confidence = 5000,
        .observe_min_hits   = 3,
        ._pad0              = 0,
        .alert_confidence   = 20000,
        .alert_min_sources  = 2,
        .alert_min_hits     = 5,
        .retract_confidence = 2000,
        ._reserved          = 0,
    };
    return cfg;
}

/* --------------------------------------------------------------------------
 * Lifecycle
 * -------------------------------------------------------------------------- */

wake_quorum_t *
wake_quorum_create(uint32_t capacity, const wake_quorum_config_t *cfg)
{
    wake_quorum_t *q = calloc(1, sizeof(wake_quorum_t));
    if (!q)
        return NULL;

    q->slots = calloc(capacity, sizeof(wake_quorum_slot_t));
    if (!q->slots) {
        free(q);
        return NULL;
    }

    q->config   = cfg ? *cfg : wake_quorum_default_config();
    q->capacity = capacity;
    return q;
}

void
wake_quorum_destroy(wake_quorum_t *q)
{
    if (!q)
        return;
    free(q->slots);
    free(q);
}

void
wake_quorum_reset(wake_quorum_t *q)
{
    if (!q)
        return;
    memset(q->slots, 0, (size_t)q->capacity * sizeof(wake_quorum_slot_t));
    q->observations_emitted = 0;
    q->alerts_emitted       = 0;
    q->retractions_emitted  = 0;
    q->suppressed           = 0;
}

void
wake_quorum_preseed(wake_quorum_t *q, const wake_pheromone_t *pt)
{
    if (!q || !pt)
        return;

    /* Dry sweep: populate emitted_tier from current pheromone state */
    wake_quorum_sweep(q, pt, NULL, NULL);

    /* Reset counters: preseed is not real emission */
    q->observations_emitted = 0;
    q->alerts_emitted       = 0;
    q->retractions_emitted  = 0;
    q->suppressed           = 0;
}

/* --------------------------------------------------------------------------
 * Sweep
 *
 * For each pheromone table slot:
 *   - Dead slots: clear emission state. If the entity was previously at
 *     ALERT tier and is now tombstoned, we do NOT emit RETRACT because
 *     the entity data is gone (peers' natural decay handles convergence).
 *
 *   - Live slots: compare current tier against emitted tier.
 *     * tier > emitted_tier: upward crossing → emit OBSERVE or ALERT.
 *       Only the highest new tier is emitted (ALERT implies OBSERVE).
 *     * emitted_tier == ALERT and confidence < retract_confidence:
 *       entity decayed while still alive → emit RETRACT.
 *     * Otherwise: suppressed (already emitted at this tier).
 *
 *   - Slot reuse: if key_hash changed, emission state is reset (new entity
 *     in the same slot after tombstone reclamation).
 * -------------------------------------------------------------------------- */

wake_quorum_sweep_result_t
wake_quorum_sweep(wake_quorum_t *q,
                   const wake_pheromone_t *pt,
                   wake_quorum_emit_fn fn,
                   void *ctx)
{
    wake_quorum_sweep_result_t result;
    memset(&result, 0, sizeof(result));

    if (!q || !pt)
        return result;

    uint32_t cap = q->capacity < pt->header->capacity
                 ? q->capacity : pt->header->capacity;

    for (uint32_t i = 0; i < cap; i++) {
        result.slots_scanned++;

        wake_pheromone_entry_t snap;
        bool live = wake_pheromone_read_entry(pt, i, &snap);

        if (!live) {
            /*
             * Slot is empty or tombstoned. Clear emission state.
             * If the entity was previously ALERT-emitted and decayed
             * past noise_floor (tombstoned), we rely on peers' natural
             * pheromone decay for convergence; no RETRACT needed.
             */
            q->slots[i].key_hash     = 0;
            q->slots[i].emitted_tier = WAKE_QUORUM_NONE;
            continue;
        }

        result.slots_live++;

        uint64_t kh = atomic_load_explicit(
            &snap.key_hash, memory_order_relaxed);

        /* Detect slot reuse: different entity in same slot */
        if (kh != q->slots[i].key_hash) {
            q->slots[i].key_hash     = kh;
            q->slots[i].emitted_tier = WAKE_QUORUM_NONE;
        }

        /* Read fields from consistent snapshot */
        uint32_t confidence = atomic_load_explicit(
            &snap.confidence, memory_order_relaxed);
        uint16_t src_count = atomic_load_explicit(
            &snap.src_count, memory_order_relaxed);
        uint32_t hit_count = atomic_load_explicit(
            &snap.hit_count, memory_order_relaxed);

        /* Classify current tier */
        wake_quorum_tier_t tier = wake_quorum_classify(
            &q->config, confidence, src_count, hit_count);

        uint8_t prev_tier = q->slots[i].emitted_tier;

        if ((uint8_t)tier > prev_tier) {
            /* New upward threshold crossing */
            wake_quorum_action_t act =
                (tier == WAKE_QUORUM_ALERT) ? WAKE_QUORUM_ACT_ALERT
                                            : WAKE_QUORUM_ACT_OBSERVE;

            q->slots[i].emitted_tier = (uint8_t)tier;

            if (act == WAKE_QUORUM_ACT_OBSERVE) {
                result.new_observations++;
                q->observations_emitted++;
            } else {
                result.new_alerts++;
                q->alerts_emitted++;
            }

            if (fn && !fn(act, i, &snap, ctx))
                break;

        } else if (prev_tier == WAKE_QUORUM_ALERT &&
                   (uint8_t)tier < WAKE_QUORUM_ALERT &&
                   confidence < q->config.retract_confidence) {
            /* Was ALERT, now decayed below retract threshold -> RETRACT */
            q->slots[i].emitted_tier = WAKE_QUORUM_NONE;
            q->slots[i].key_hash     = 0; /* allow re-emission on rise */

            result.new_retractions++;
            q->retractions_emitted++;

            if (fn && !fn(WAKE_QUORUM_ACT_RETRACT, i, &snap, ctx))
                break;

        } else {
            result.suppressed++;
            q->suppressed++;
        }
    }

    return result;
}

/* --------------------------------------------------------------------------
 * Callback-free sweep (HardenedBSD / W^X compatible)
 * -------------------------------------------------------------------------- */

wake_quorum_sweep_result_t
wake_quorum_sweep_collect(wake_quorum_t *q,
                           const wake_pheromone_t *pt,
                           wake_quorum_hit_t *hits,
                           uint32_t hits_capacity,
                           uint32_t *hits_count)
{
    wake_quorum_sweep_result_t result;
    memset(&result, 0, sizeof(result));

    uint32_t written = 0;

    if (!q || !pt) {
        if (hits_count)
            *hits_count = 0;
        return result;
    }

    uint32_t cap = q->capacity < pt->header->capacity
                 ? q->capacity : pt->header->capacity;

    for (uint32_t i = 0; i < cap; i++) {
        result.slots_scanned++;

        wake_pheromone_entry_t snap;
        bool live = wake_pheromone_read_entry(pt, i, &snap);

        if (!live) {
            q->slots[i].key_hash     = 0;
            q->slots[i].emitted_tier = WAKE_QUORUM_NONE;
            continue;
        }

        result.slots_live++;

        uint64_t kh = atomic_load_explicit(
            &snap.key_hash, memory_order_relaxed);

        if (kh != q->slots[i].key_hash) {
            q->slots[i].key_hash     = kh;
            q->slots[i].emitted_tier = WAKE_QUORUM_NONE;
        }

        uint32_t confidence = atomic_load_explicit(
            &snap.confidence, memory_order_relaxed);
        uint16_t src_count = atomic_load_explicit(
            &snap.src_count, memory_order_relaxed);
        uint32_t hit_count = atomic_load_explicit(
            &snap.hit_count, memory_order_relaxed);

        wake_quorum_tier_t tier = wake_quorum_classify(
            &q->config, confidence, src_count, hit_count);

        uint8_t prev_tier = q->slots[i].emitted_tier;

        if ((uint8_t)tier > prev_tier) {
            wake_quorum_action_t act =
                (tier == WAKE_QUORUM_ALERT) ? WAKE_QUORUM_ACT_ALERT
                                            : WAKE_QUORUM_ACT_OBSERVE;

            q->slots[i].emitted_tier = (uint8_t)tier;

            if (act == WAKE_QUORUM_ACT_OBSERVE) {
                result.new_observations++;
                q->observations_emitted++;
            } else {
                result.new_alerts++;
                q->alerts_emitted++;
            }

            if (hits && written < hits_capacity) {
                hits[written].action   = act;
                hits[written].slot_idx = i;
                hits[written].entry    = snap;
                written++;
            }

        } else if (prev_tier == WAKE_QUORUM_ALERT &&
                   (uint8_t)tier < WAKE_QUORUM_ALERT &&
                   confidence < q->config.retract_confidence) {
            q->slots[i].emitted_tier = WAKE_QUORUM_NONE;
            q->slots[i].key_hash     = 0;

            result.new_retractions++;
            q->retractions_emitted++;

            if (hits && written < hits_capacity) {
                hits[written].action   = WAKE_QUORUM_ACT_RETRACT;
                hits[written].slot_idx = i;
                hits[written].entry    = snap;
                written++;
            }

        } else {
            result.suppressed++;
            q->suppressed++;
        }
    }

    if (hits_count)
        *hits_count = written;

    return result;
}

/* --------------------------------------------------------------------------
 * Name accessors
 * -------------------------------------------------------------------------- */

static const char *tier_names[] = {
    "NONE", "OBSERVE", "ALERT"
};

static const char *action_names[] = {
    "NONE", "OBSERVE", "ALERT", "RETRACT"
};

const char *
wake_quorum_tier_name(wake_quorum_tier_t tier)
{
    if ((unsigned)tier < WAKE_QUORUM__COUNT)
        return tier_names[(unsigned)tier];
    return "UNKNOWN";
}

const char *
wake_quorum_action_name(wake_quorum_action_t action)
{
    if ((unsigned)action <= 3)
        return action_names[(unsigned)action];
    return "UNKNOWN";
}
