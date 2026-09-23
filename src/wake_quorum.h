/*
 * wake_quorum.h: WAKE Quorum Evaluator
 *
 * Threshold-based signal emission engine inspired by bacterial quorum sensing.
 * Evaluates accumulated pheromone confidence to decide when mesh signals
 * (OBSERVATION, ALERT, RETRACT) should be emitted.
 *
 * Two evaluation contexts:
 *
 *   1. Inline (hot path): wake_quorum_check_inline()
 *      Fast threshold comparison after a pheromone deposit. Returns true if
 *      confidence warrants attention from the host application. Zero state, zero
 *      allocation. A host may call this after a deposit to decide whether to
 *      schedule a sweep.
 *
 *   2. Sweep (cold path): wake_quorum_sweep()
 *      Periodic scan of the pheromone table by the host application. Tracks per-slot
 *      emission state to avoid duplicate signals. Detects:
 *        - New OBSERVE threshold crossings -> emit OBSERVATION signal
 *        - New ALERT threshold crossings  -> emit ALERT signal
 *        - A still-live entry emitted as ALERT, now below the ALERT tier
 *          and below retract_confidence, yields RETRACT. Eviction emits
 *          nothing.
 *
 * Threshold tiers:
 *   OBSERVE: local confidence sufficient for tenant-scoped sharing.
 *     Requires: confidence >= observe_confidence AND hits >= observe_min_hits
 *     Maps to: WAKE_SIG_OBSERVATION, WAKE_SCOPE_TENANT
 *
 *   ALERT: high confidence with multi-source corroboration.
 *     Requires: confidence >= alert_confidence AND sources >= alert_min_sources
 *               AND hits >= alert_min_hits
 *     Maps to: WAKE_SIG_ALERT, WAKE_SCOPE_FLEET
 *
 * Bio-inspiration: in quorum sensing, bacteria produce and detect
 * autoinducers (signaling molecules). When concentration crosses a
 * threshold, collective behavior is triggered. The two tiers are:
 *   - OBSERVE: tenant-local, lower threshold
 *   - ALERT: fleet-wide, requires multiple producers
 *
 * Copyright (c) 2026 Advens. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef WAKE_QUORUM_H
#define WAKE_QUORUM_H

#include "wake_pheromone.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* --------------------------------------------------------------------------
 * Threshold tiers (ascending severity)
 * -------------------------------------------------------------------------- */
typedef enum {
    WAKE_QUORUM_NONE    = 0,   /* Below all thresholds */
    WAKE_QUORUM_OBSERVE = 1,   /* Sufficient for mesh observation signal */
    WAKE_QUORUM_ALERT   = 2,   /* Sufficient for alert signal */
    WAKE_QUORUM__COUNT  = 3
} wake_quorum_tier_t;

/* --------------------------------------------------------------------------
 * Actions the evaluator recommends during sweep
 * -------------------------------------------------------------------------- */
typedef enum {
    WAKE_QUORUM_ACT_NONE    = 0,  /* No action needed */
    WAKE_QUORUM_ACT_OBSERVE = 1,  /* Emit OBSERVATION signal (TENANT scope) */
    WAKE_QUORUM_ACT_ALERT   = 2,  /* Emit ALERT signal (FLEET scope) */
    WAKE_QUORUM_ACT_RETRACT = 3,  /* Emit RETRACT (was ALERT, now decayed) */
} wake_quorum_action_t;

/* --------------------------------------------------------------------------
 * Configuration: 24 bytes
 *
 * Defaults are absolute counts: observe 5000, alert 20000, retract 2000.
 * This library does not score individual events.
 * -------------------------------------------------------------------------- */
typedef struct {
    /* Observation tier: local evidence sufficient for mesh sharing */
    uint32_t observe_confidence;  /* Min confidence (default: 5000)       */
    uint16_t observe_min_hits;    /* Min hit count (default: 3)           */
    uint16_t _pad0;

    /* Alert tier: high confidence + multi-source corroboration */
    uint32_t alert_confidence;    /* Min confidence (default: 20000)      */
    uint16_t alert_min_sources;   /* Min independent sources (default: 2) */
    uint16_t alert_min_hits;      /* Min hit count (default: 5)           */

    /* Retraction: ALERT entity decayed below this -> RETRACT */
    uint32_t retract_confidence;  /* Below this -> retract (default: 2000) */

    uint32_t _reserved;
} wake_quorum_config_t;

_Static_assert(sizeof(wake_quorum_config_t) == 24,
    "quorum config must be exactly 24 bytes");

/* --------------------------------------------------------------------------
 * Per-slot emission tracking: 16 bytes
 *
 * Parallel to pheromone table entries. Tracks what signals have been
 * emitted for each slot to prevent duplicate emissions.
 *
 * key_hash detects slot reuse: when the pheromone table recycles a
 * slot for a different entity, emission state is reset.
 * -------------------------------------------------------------------------- */
typedef struct {
    uint64_t key_hash;       /* Entity key_hash for reuse detection */
    uint8_t  emitted_tier;   /* Highest wake_quorum_tier_t emitted  */
    uint8_t  _pad[7];
} wake_quorum_slot_t;

_Static_assert(sizeof(wake_quorum_slot_t) == 16,
    "quorum slot must be exactly 16 bytes");

/* --------------------------------------------------------------------------
 * Evaluator state (owned by the host application, not shared across processes)
 * -------------------------------------------------------------------------- */
typedef struct {
    wake_quorum_config_t  config;
    wake_quorum_slot_t   *slots;      /* [capacity] parallel to pheromone */
    uint32_t              capacity;   /* Same as pheromone table capacity */
    uint32_t              _pad;

    /* Lifetime counters */
    uint64_t  observations_emitted;
    uint64_t  alerts_emitted;
    uint64_t  retractions_emitted;
    uint64_t  suppressed;
} wake_quorum_t;

/* --------------------------------------------------------------------------
 * Sweep result counters (per-sweep)
 * -------------------------------------------------------------------------- */
typedef struct {
    uint32_t slots_scanned;        /* Total slots iterated */
    uint32_t slots_live;           /* Slots with live entries */
    uint32_t new_observations;     /* New OBSERVE threshold crossings */
    uint32_t new_alerts;           /* New ALERT threshold crossings */
    uint32_t new_retractions;      /* New RETRACT actions */
    uint32_t suppressed;           /* Already emitted at current tier */
} wake_quorum_sweep_result_t;

/* --------------------------------------------------------------------------
 * Configuration
 * -------------------------------------------------------------------------- */

/* Returns a config with production-calibrated defaults. */
wake_quorum_config_t wake_quorum_default_config(void);

/* --------------------------------------------------------------------------
 * Pure evaluation functions (hot path, no state, no side effects)
 * -------------------------------------------------------------------------- */

/*
 * Classify the current tier for an entity based on its pheromone state.
 *
 * Returns the highest tier whose criteria are met.
 * Pure function: no side effects, no state.
 */
static inline wake_quorum_tier_t
wake_quorum_classify(const wake_quorum_config_t *cfg,
                     uint32_t confidence,
                     uint16_t src_count,
                     uint32_t hit_count)
{
    if (confidence >= cfg->alert_confidence &&
        src_count >= cfg->alert_min_sources &&
        hit_count >= cfg->alert_min_hits) {
        return WAKE_QUORUM_ALERT;
    }
    if (confidence >= cfg->observe_confidence &&
        hit_count >= cfg->observe_min_hits) {
        return WAKE_QUORUM_OBSERVE;
    }
    return WAKE_QUORUM_NONE;
}

/*
 * Fast inline threshold check for wake hot path.
 *
 * Returns true if confidence warrants the host application's attention.
 * Conservative overestimate: only checks confidence, not hit_count
 * or src_count. False positives are filtered by the sweep.
 */
static inline bool
wake_quorum_check_inline(const wake_quorum_config_t *cfg,
                          uint32_t confidence)
{
    return confidence >= cfg->observe_confidence;
}

/* --------------------------------------------------------------------------
 * Evaluator lifecycle
 * -------------------------------------------------------------------------- */

/*
 * Create a quorum evaluator with per-slot tracking.
 *
 * capacity must match the pheromone table's capacity.
 * Memory: 16 bytes per slot (1 MiB for 64K slots).
 *
 * Returns NULL on allocation failure.
 */
wake_quorum_t *wake_quorum_create(uint32_t capacity,
                                   const wake_quorum_config_t *cfg);

/*
 * Destroy the evaluator and free slot tracking memory.
 */
void wake_quorum_destroy(wake_quorum_t *q);

/*
 * Reset all emission state and counters. Use after major table changes
 * (e.g., table recreation, bulk retraction).
 */
void wake_quorum_reset(wake_quorum_t *q);

/*
 * Pre-seed emission state from an existing pheromone table.
 *
 * Runs a dry sweep (no emit callback) to populate emitted_tier for every
 * live slot, then resets lifetime counters to zero. Call this once after
 * wake_quorum_create() when reopening a persisted pheromone table so
 * that the first real sweep does not re-emit for entities already above
 * threshold.
 */
void wake_quorum_preseed(wake_quorum_t *q, const wake_pheromone_t *pt);

/* --------------------------------------------------------------------------
 * Sweep (cold path, called by the host application's timer)
 * -------------------------------------------------------------------------- */

/*
 * Sweep callback. Called for each entity that needs signal action.
 *
 * Parameters:
 *   action: recommended action (OBSERVE, ALERT, or RETRACT)
 *   slot_idx: pheromone table slot index
 *   entry: consistent snapshot of the pheromone entry
 *   ctx: caller-provided context
 *
 * Return false to stop iteration.
 */
typedef bool (*wake_quorum_emit_fn)(
    wake_quorum_action_t action,
    uint32_t slot_idx,
    const wake_pheromone_entry_t *entry,
    void *ctx);

/*
 * Scan the pheromone table, evaluate thresholds, call the emit callback
 * for each entity that needs signal action.
 *
 * Updates per-slot emission state to prevent duplicate signals.
 * Detects:
 *   - Upward threshold crossings (OBSERVE, ALERT)
 *   - A still-live entry emitted as ALERT, now below the ALERT tier and
 *     below retract_confidence, yields RETRACT. Eviction emits nothing.
 *   - Slot reuse (emission state reset)
 *
 * fn may be NULL (dry run: updates emission state without callbacks).
 */
wake_quorum_sweep_result_t wake_quorum_sweep(
    wake_quorum_t *q,
    const wake_pheromone_t *pt,
    wake_quorum_emit_fn fn,
    void *ctx);

/* --------------------------------------------------------------------------
 * Callback-free sweep
 *
 * Writes hits into a caller-owned array so a host can sweep without a
 * callback.
 * -------------------------------------------------------------------------- */
typedef struct {
    wake_quorum_action_t    action;
    uint32_t                slot_idx;
    wake_pheromone_entry_t  entry;   /* consistent snapshot */
} wake_quorum_hit_t;

/*
 * Sweep with collection. Same semantics as wake_quorum_sweep() but
 * writes hits to a pre-allocated array instead of calling a callback.
 *
 * All entries are evaluated and emission state is updated regardless of
 * hits_capacity. Only the first hits_capacity crossings are recorded.
 *
 * *hits_count is set to the actual number of hits written (<= hits_capacity).
 */
wake_quorum_sweep_result_t wake_quorum_sweep_collect(
    wake_quorum_t *q,
    const wake_pheromone_t *pt,
    wake_quorum_hit_t *hits,
    uint32_t hits_capacity,
    uint32_t *hits_count);

/* --------------------------------------------------------------------------
 * Name accessors
 * -------------------------------------------------------------------------- */

const char *wake_quorum_tier_name(wake_quorum_tier_t tier);
const char *wake_quorum_action_name(wake_quorum_action_t action);

#ifdef __cplusplus
}
#endif

#endif /* WAKE_QUORUM_H */
