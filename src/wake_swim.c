/*
 * wake_swim.c: WAKE SWIM Membership Protocol implementation
 *
 * Event-driven membership state machine with incarnation-based precedence,
 * Fisher-Yates probe ordering, and piggybacked update dissemination.
 *
 * All time is injected via now_ms parameters: no internal clocks.
 * Single-threaded: owned and operated by the host application's main loop.
 *
 * Copyright (c) 2026 Advens. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "wake_swim.h"

#include <stdlib.h>
#include <string.h>

/* --------------------------------------------------------------------------
 * Internal helpers
 * -------------------------------------------------------------------------- */

/* Log2 approximation (integer, floor). Returns 0 for n <= 1. */
static uint32_t
ilog2(uint32_t n)
{
    if (n <= 1)
        return 0;
    uint32_t r = 0;
    while (n > 1) {
        n >>= 1;
        r++;
    }
    return r;
}

/* Find member by node_id. Returns index, or -1 if not found. */
static int
find_member(const wake_swim_t *sw, const uint8_t node_id[WAKE_SWIM_NODE_ID_LEN])
{
    for (uint32_t i = 0; i < sw->member_count; i++) {
        if (memcmp(sw->members[i].node_id, node_id,
                   WAKE_SWIM_NODE_ID_LEN) == 0) {
            return (int)i;
        }
    }
    return -1;
}

/* Check if node_id matches self. */
static bool
is_self(const wake_swim_t *sw, const uint8_t node_id[WAKE_SWIM_NODE_ID_LEN])
{
    return memcmp(sw->self_id, node_id, WAKE_SWIM_NODE_ID_LEN) == 0;
}

/* Recount alive_count from member list. */
static void
recount_alive(wake_swim_t *sw)
{
    uint32_t count = 0;
    for (uint32_t i = 0; i < sw->member_count; i++) {
        uint8_t s = sw->members[i].state;
        if (s == WAKE_SWIM_ALIVE || s == WAKE_SWIM_SUSPECT)
            count++;
    }
    sw->alive_count = count;
}

/* Queue a dissemination update. Overwrites existing update for same node. */
static void
queue_update(wake_swim_t *sw, const wake_swim_member_t *m)
{
    /* Check if we already have an update for this node_id */
    for (uint32_t i = 0; i < sw->update_count; i++) {
        if (memcmp(sw->updates[i].node_id, m->node_id,
                   WAKE_SWIM_NODE_ID_LEN) == 0) {
            /* Replace with newer update */
            memcpy(sw->updates[i].node_id, m->node_id,
                   WAKE_SWIM_NODE_ID_LEN);
            sw->updates[i].addr        = m->addr;
            sw->updates[i].port        = m->port;
            sw->updates[i].state       = m->state;
            sw->updates[i].incarnation = m->incarnation;
            sw->updates[i].piggyback_count = 0;
            sw->updates[i]._pad0       = 0;
            sw->updates[i]._pad1       = 0;
            return;
        }
    }

    /* Not found: add new entry */
    if (sw->update_count < sw->config.update_queue_size) {
        wake_swim_update_t *u = &sw->updates[sw->update_count];
        memcpy(u->node_id, m->node_id, WAKE_SWIM_NODE_ID_LEN);
        u->addr            = m->addr;
        u->port            = m->port;
        u->state           = m->state;
        u->incarnation     = m->incarnation;
        u->piggyback_count = 0;
        u->_pad0           = 0;
        u->_pad1           = 0;
        sw->update_count++;
        sw->updates_queued++;
    } else {
        /* Queue full: evict highest piggyback_count entry */
        uint32_t worst = 0;
        uint16_t worst_pb = sw->updates[0].piggyback_count;
        for (uint32_t i = 1; i < sw->update_count; i++) {
            if (sw->updates[i].piggyback_count > worst_pb) {
                worst_pb = sw->updates[i].piggyback_count;
                worst = i;
            }
        }
        wake_swim_update_t *u = &sw->updates[worst];
        memcpy(u->node_id, m->node_id, WAKE_SWIM_NODE_ID_LEN);
        u->addr            = m->addr;
        u->port            = m->port;
        u->state           = m->state;
        u->incarnation     = m->incarnation;
        u->piggyback_count = 0;
        u->_pad0           = 0;
        u->_pad1           = 0;
        sw->updates_queued++;
    }
}

/* Build the probe order array from current alive/suspect members. */
static void
rebuild_probe_order(wake_swim_t *sw)
{
    sw->probe_size = 0;
    for (uint32_t i = 0; i < sw->member_count; i++) {
        uint8_t s = sw->members[i].state;
        if (s == WAKE_SWIM_ALIVE || s == WAKE_SWIM_SUSPECT) {
            sw->probe_order[sw->probe_size++] = i;
        }
    }

    /* Fisher-Yates shuffle */
    for (uint32_t i = sw->probe_size; i > 1; i--) {
        uint64_t r = wake_splitmix64(&sw->prng_state);
        uint32_t j = (uint32_t)(r % (uint64_t)i);
        uint32_t tmp = sw->probe_order[i - 1];
        sw->probe_order[i - 1] = sw->probe_order[j];
        sw->probe_order[j] = tmp;
    }

    sw->probe_index = 0;
}

/*
 * State precedence check.
 * Returns true if (new_state, new_inc) supersedes (old_state, old_inc).
 *
 * Rules:
 *   - LEFT always wins (voluntary departure is final)
 *   - Higher incarnation always wins
 *   - Same incarnation: DEAD > SUSPECT > ALIVE
 */
static bool
state_supersedes(uint8_t new_state, uint32_t new_inc,
                 uint8_t old_state, uint32_t old_inc)
{
    /* LEFT always wins */
    if (new_state == WAKE_SWIM_LEFT)
        return true;
    /* Cannot override LEFT */
    if (old_state == WAKE_SWIM_LEFT)
        return false;
    /* Higher incarnation wins */
    if (new_inc > old_inc)
        return true;
    if (new_inc < old_inc)
        return false;
    /* Same incarnation: higher state value wins (DEAD > SUSPECT > ALIVE) */
    return new_state > old_state;
}

/* --------------------------------------------------------------------------
 * Default configuration
 * -------------------------------------------------------------------------- */

wake_swim_config_t
wake_swim_default_config(void)
{
    wake_swim_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.max_members       = 512;
    cfg.update_queue_size = 256;
    cfg.suspicion_mult    = 5;
    cfg.max_piggybacks    = 8;
    cfg.protocol_period_ms = 1000;
    cfg.suspect_timeout_ms = 0;  /* auto-calculate */
    cfg.prng_seed          = 0;  /* use time-based */
    return cfg;
}

/* --------------------------------------------------------------------------
 * Lifecycle
 * -------------------------------------------------------------------------- */

wake_swim_t *
wake_swim_create(const uint8_t self_id[WAKE_SWIM_NODE_ID_LEN],
                  uint32_t self_addr, uint16_t self_port,
                  const wake_swim_config_t *cfg)
{
    if (!self_id)
        return NULL;

    wake_swim_t *sw = calloc(1, sizeof(wake_swim_t));
    if (!sw)
        return NULL;

    sw->config = cfg ? *cfg : wake_swim_default_config();

    /* Enforce minimums */
    if (sw->config.max_members == 0)
        sw->config.max_members = 512;
    if (sw->config.update_queue_size == 0)
        sw->config.update_queue_size = 256;
    if (sw->config.suspicion_mult == 0)
        sw->config.suspicion_mult = 5;
    if (sw->config.max_piggybacks == 0)
        sw->config.max_piggybacks = 8;
    if (sw->config.protocol_period_ms == 0)
        sw->config.protocol_period_ms = 1000;

    sw->members = calloc(sw->config.max_members,
                          sizeof(wake_swim_member_t));
    sw->probe_order = calloc(sw->config.max_members, sizeof(uint32_t));
    sw->updates = calloc(sw->config.update_queue_size,
                          sizeof(wake_swim_update_t));

    if (!sw->members || !sw->probe_order || !sw->updates) {
        free(sw->members);
        free(sw->probe_order);
        free(sw->updates);
        free(sw);
        return NULL;
    }

    memcpy(sw->self_id, self_id, WAKE_SWIM_NODE_ID_LEN);
    sw->self_addr       = self_addr;
    sw->self_port       = self_port;
    sw->self_incarnation = 0;

    /* Seed PRNG */
    if (sw->config.prng_seed != 0) {
        sw->prng_state = sw->config.prng_seed;
    } else {
        /* Time-based seed. Not cryptographic: just for shuffling. */
        sw->prng_state = (uint64_t)((uintptr_t)sw) ^ UINT64_C(0xDEADBEEFCAFE);
    }

    return sw;
}

void
wake_swim_destroy(wake_swim_t *sw)
{
    if (!sw)
        return;
    free(sw->members);
    free(sw->probe_order);
    free(sw->updates);
    free(sw);
}

void
wake_swim_reset(wake_swim_t *sw)
{
    if (!sw)
        return;
    memset(sw->members, 0,
           (size_t)sw->config.max_members * sizeof(wake_swim_member_t));
    memset(sw->updates, 0,
           (size_t)sw->config.update_queue_size * sizeof(wake_swim_update_t));
    sw->member_count = 0;
    sw->alive_count  = 0;
    sw->probe_size   = 0;
    sw->probe_index  = 0;
    sw->update_count = 0;
    sw->rounds_completed     = 0;
    sw->state_changes        = 0;
    sw->updates_queued       = 0;
    sw->updates_piggybacked  = 0;
    sw->suspects_expired     = 0;
    sw->health_score         = 0;
}

/* --------------------------------------------------------------------------
 * Member management
 * -------------------------------------------------------------------------- */

wake_swim_result_t
wake_swim_add_member(wake_swim_t *sw,
                      const uint8_t node_id[WAKE_SWIM_NODE_ID_LEN],
                      uint32_t addr, uint16_t port,
                      uint64_t now_ms)
{
    if (!sw || !node_id)
        return WAKE_SWIM_NOT_FOUND;

    if (is_self(sw, node_id))
        return WAKE_SWIM_SELF;

    if (find_member(sw, node_id) >= 0)
        return WAKE_SWIM_EXISTS;

    if (sw->member_count >= sw->config.max_members)
        return WAKE_SWIM_FULL;

    wake_swim_member_t *m = &sw->members[sw->member_count];
    memset(m, 0, sizeof(*m));
    memcpy(m->node_id, node_id, WAKE_SWIM_NODE_ID_LEN);
    m->addr            = addr;
    m->port            = port;
    m->state           = WAKE_SWIM_ALIVE;
    m->incarnation     = 0;
    m->last_change_ms  = now_ms;
    m->suspect_ms      = 0;

    sw->member_count++;
    sw->alive_count++;
    sw->state_changes++;

    /* Queue dissemination update */
    queue_update(sw, m);

    /* Invalidate probe order (new member added) */
    sw->probe_size = 0;

    return WAKE_SWIM_OK;
}

wake_swim_result_t
wake_swim_remove_member(wake_swim_t *sw,
                         const uint8_t node_id[WAKE_SWIM_NODE_ID_LEN],
                         uint64_t now_ms)
{
    if (!sw || !node_id)
        return WAKE_SWIM_NOT_FOUND;

    if (is_self(sw, node_id))
        return WAKE_SWIM_SELF;

    int idx = find_member(sw, node_id);
    if (idx < 0)
        return WAKE_SWIM_NOT_FOUND;

    wake_swim_member_t *m = &sw->members[idx];
    m->state          = WAKE_SWIM_LEFT;
    m->last_change_ms = now_ms;
    m->suspect_ms     = 0;
    sw->state_changes++;

    recount_alive(sw);
    queue_update(sw, m);

    /* Invalidate probe order */
    sw->probe_size = 0;

    return WAKE_SWIM_OK;
}

const wake_swim_member_t *
wake_swim_find(const wake_swim_t *sw,
                const uint8_t node_id[WAKE_SWIM_NODE_ID_LEN])
{
    if (!sw || !node_id)
        return NULL;

    int idx = find_member(sw, node_id);
    if (idx < 0)
        return NULL;

    return &sw->members[idx];
}

/* --------------------------------------------------------------------------
 * State machine: incarnation-based updates
 * -------------------------------------------------------------------------- */

wake_swim_result_t
wake_swim_apply_update(wake_swim_t *sw,
                        const wake_swim_update_t *update,
                        uint64_t now_ms)
{
    if (!sw || !update)
        return WAKE_SWIM_STALE;

    /* Self-refutation: if someone suspects/kills us, refute */
    if (is_self(sw, update->node_id)) {
        if (update->state == WAKE_SWIM_SUSPECT ||
            update->state == WAKE_SWIM_DEAD) {
            /*
             * Increment our incarnation past the update's and queue
             * an ALIVE update to refute the suspicion.
             */
            if (update->incarnation >= sw->self_incarnation)
                sw->self_incarnation = update->incarnation + 1;

            /* Build a self-refutation update */
            wake_swim_member_t self_m;
            memset(&self_m, 0, sizeof(self_m));
            memcpy(self_m.node_id, sw->self_id, WAKE_SWIM_NODE_ID_LEN);
            self_m.addr        = sw->self_addr;
            self_m.port        = sw->self_port;
            self_m.state       = WAKE_SWIM_ALIVE;
            self_m.incarnation = sw->self_incarnation;
            self_m.last_change_ms = now_ms;
            queue_update(sw, &self_m);
            return WAKE_SWIM_OK;
        }
        /* ALIVE update about self: just bump incarnation if higher */
        if (update->incarnation > sw->self_incarnation)
            sw->self_incarnation = update->incarnation;
        return WAKE_SWIM_NOOP;
    }

    /* Find existing member */
    int idx = find_member(sw, update->node_id);

    if (idx < 0) {
        /* Unknown member: only add if the update says ALIVE */
        if (update->state == WAKE_SWIM_ALIVE) {
            wake_swim_result_t r = wake_swim_add_member(
                sw, update->node_id, update->addr, update->port, now_ms);
            if (r == WAKE_SWIM_OK) {
                /* Set incarnation from update */
                int new_idx = find_member(sw, update->node_id);
                if (new_idx >= 0) {
                    sw->members[new_idx].incarnation = update->incarnation;
                }
            }
            return r;
        }
        return WAKE_SWIM_NOT_FOUND;
    }

    wake_swim_member_t *m = &sw->members[idx];

    /* Check precedence */
    if (!state_supersedes(update->state, update->incarnation,
                          m->state, m->incarnation)) {
        if (update->state == m->state &&
            update->incarnation == m->incarnation) {
            return WAKE_SWIM_NOOP;
        }
        return WAKE_SWIM_STALE;
    }

    /* Apply the update */
    m->state          = update->state;
    m->incarnation    = update->incarnation;
    m->addr           = update->addr;
    m->port           = update->port;
    m->last_change_ms = now_ms;

    if (update->state == WAKE_SWIM_SUSPECT) {
        m->suspect_ms = now_ms;
    } else {
        m->suspect_ms = 0;
    }

    sw->state_changes++;
    recount_alive(sw);
    queue_update(sw, m);

    /* Invalidate probe order on state changes */
    sw->probe_size = 0;

    return WAKE_SWIM_OK;
}

wake_swim_result_t
wake_swim_suspect_member(wake_swim_t *sw,
                          const uint8_t node_id[WAKE_SWIM_NODE_ID_LEN],
                          uint64_t now_ms)
{
    if (!sw || !node_id)
        return WAKE_SWIM_NOT_FOUND;

    if (is_self(sw, node_id))
        return WAKE_SWIM_SELF;

    int idx = find_member(sw, node_id);
    if (idx < 0)
        return WAKE_SWIM_NOT_FOUND;

    wake_swim_member_t *m = &sw->members[idx];
    if (m->state != WAKE_SWIM_ALIVE)
        return WAKE_SWIM_STALE;

    m->state          = WAKE_SWIM_SUSPECT;
    m->suspect_ms     = now_ms;
    m->last_change_ms = now_ms;
    sw->state_changes++;

    recount_alive(sw);  /* suspect still counts as alive for probing */
    queue_update(sw, m);

    /* Invalidate probe order */
    sw->probe_size = 0;

    return WAKE_SWIM_OK;
}

/* --------------------------------------------------------------------------
 * Protocol actions
 * -------------------------------------------------------------------------- */

const wake_swim_member_t *
wake_swim_next_probe(wake_swim_t *sw)
{
    if (!sw || sw->alive_count == 0)
        return NULL;

    /* Rebuild probe order if needed */
    if (sw->probe_size == 0 || sw->probe_index >= sw->probe_size) {
        rebuild_probe_order(sw);
        if (sw->probe_size == 0)
            return NULL;
        if (sw->probe_index >= sw->probe_size) {
            sw->rounds_completed++;
        }
    }

    /* Find next valid probe target */
    while (sw->probe_index < sw->probe_size) {
        uint32_t idx = sw->probe_order[sw->probe_index++];
        if (idx < sw->member_count) {
            uint8_t s = sw->members[idx].state;
            if (s == WAKE_SWIM_ALIVE || s == WAKE_SWIM_SUSPECT) {
                return &sw->members[idx];
            }
        }
        /* Member state changed since we built the order: skip */
    }

    /* All entries were stale, rebuild and try once more */
    rebuild_probe_order(sw);
    sw->rounds_completed++;
    if (sw->probe_size == 0)
        return NULL;

    uint32_t idx = sw->probe_order[sw->probe_index++];
    if (idx < sw->member_count) {
        uint8_t s = sw->members[idx].state;
        if (s == WAKE_SWIM_ALIVE || s == WAKE_SWIM_SUSPECT) {
            return &sw->members[idx];
        }
    }

    return NULL;
}

uint32_t
wake_swim_select_delegates(wake_swim_t *sw,
                            const uint8_t exclude_id[WAKE_SWIM_NODE_ID_LEN],
                            wake_swim_member_t *out,
                            uint32_t max)
{
    if (!sw || !out || max == 0)
        return 0;

    /*
     * Build a list of eligible members (ALIVE, not self, not excluded).
     * Then randomly select up to `max` from them.
     */
    uint32_t eligible[512]; /* Stack buffer, capped at max_members */
    uint32_t elig_count = 0;
    uint32_t cap = sw->member_count < 512 ? sw->member_count : 512;

    for (uint32_t i = 0; i < cap; i++) {
        if (sw->members[i].state != WAKE_SWIM_ALIVE)
            continue;
        if (is_self(sw, sw->members[i].node_id))
            continue;
        if (exclude_id &&
            memcmp(sw->members[i].node_id, exclude_id,
                   WAKE_SWIM_NODE_ID_LEN) == 0)
            continue;
        eligible[elig_count++] = i;
    }

    if (elig_count == 0)
        return 0;

    /* Fisher-Yates partial shuffle: pick min(max, elig_count) */
    uint32_t pick = max < elig_count ? max : elig_count;
    for (uint32_t i = 0; i < pick; i++) {
        uint64_t r = wake_splitmix64(&sw->prng_state);
        uint32_t j = i + (uint32_t)(r % (uint64_t)(elig_count - i));
        uint32_t tmp = eligible[i];
        eligible[i] = eligible[j];
        eligible[j] = tmp;
        out[i] = sw->members[eligible[i]];
    }

    return pick;
}

/* --------------------------------------------------------------------------
 * Suspicion management
 * -------------------------------------------------------------------------- */

uint32_t
wake_swim_suspect_timeout(const wake_swim_t *sw)
{
    if (!sw)
        return 0;

    uint32_t base;
    if (sw->config.suspect_timeout_ms != 0) {
        base = sw->config.suspect_timeout_ms;
    } else {
        /* Auto: suspicion_mult * log2(max(2, alive_count)) * protocol_period */
        uint32_t n = sw->alive_count > 2 ? sw->alive_count : 2;
        uint32_t log_n = ilog2(n);
        if (log_n == 0)
            log_n = 1;
        uint64_t auto_ms = (uint64_t)sw->config.suspicion_mult * log_n * sw->config.protocol_period_ms;
        base = auto_ms > UINT32_MAX ? UINT32_MAX : (uint32_t)auto_ms;
    }

    /* Local Health Multiplier: widen (never narrow) under self-detected
     * overload. The auto base and the scaling are both computed in 64 bits and
     * saturated rather than left to wrap. */
    uint64_t scaled = (uint64_t)base * (1u + sw->health_score);
    return scaled > UINT32_MAX ? UINT32_MAX : (uint32_t)scaled;
}

void
wake_swim_report_health(wake_swim_t *sw, int delta)
{
    if (!sw)
        return;

    int64_t h = (int64_t)sw->health_score + delta;
    if (h < 0)
        h = 0;
    if (h > (int64_t)WAKE_SWIM_HEALTH_MAX)
        h = (int64_t)WAKE_SWIM_HEALTH_MAX;
    sw->health_score = (uint32_t)h;
}

uint32_t
wake_swim_health(const wake_swim_t *sw)
{
    return sw ? sw->health_score : 0;
}

uint32_t
wake_swim_check_suspects(wake_swim_t *sw, uint64_t now_ms)
{
    if (!sw)
        return 0;

    uint32_t timeout = wake_swim_suspect_timeout(sw);
    uint32_t expired = 0;

    for (uint32_t i = 0; i < sw->member_count; i++) {
        wake_swim_member_t *m = &sw->members[i];
        if (m->state != WAKE_SWIM_SUSPECT)
            continue;
        if (m->suspect_ms == 0)
            continue;

        if (now_ms - m->suspect_ms >= (uint64_t)timeout) {
            m->state          = WAKE_SWIM_DEAD;
            m->last_change_ms = now_ms;
            m->suspect_ms     = 0;
            expired++;
            sw->state_changes++;
            sw->suspects_expired++;
            queue_update(sw, m);
        }
    }

    if (expired > 0) {
        recount_alive(sw);
        sw->probe_size = 0; /* invalidate probe order */
    }

    return expired;
}

uint32_t
wake_swim_reap(wake_swim_t *sw, uint64_t now_ms, uint64_t retention_ms)
{
    if (!sw)
        return 0;

    uint32_t reaped = 0;
    uint32_t dst = 0;

    for (uint32_t src = 0; src < sw->member_count; src++) {
        wake_swim_member_t *m = &sw->members[src];
        bool is_terminal = (m->state == WAKE_SWIM_DEAD ||
                            m->state == WAKE_SWIM_LEFT);

        if (is_terminal && now_ms - m->last_change_ms >= retention_ms) {
            /* Reap this entry */
            reaped++;
            continue;
        }

        /* Keep this entry, compact if needed */
        if (dst != src) {
            sw->members[dst] = sw->members[src];
        }
        dst++;
    }

    sw->member_count = dst;
    if (reaped > 0) {
        recount_alive(sw);
        sw->probe_size = 0; /* invalidate probe order */
    }

    return reaped;
}

/* --------------------------------------------------------------------------
 * Dissemination queue
 * -------------------------------------------------------------------------- */

uint32_t
wake_swim_get_updates(wake_swim_t *sw,
                       wake_swim_update_t *out,
                       uint32_t max)
{
    if (!sw || !out || max == 0 || sw->update_count == 0)
        return 0;

    uint32_t pick = max < sw->update_count ? max : sw->update_count;

    /*
     * Sort by piggyback_count (selection sort: queue is small).
     * We pick the `pick` updates with lowest piggyback_count.
     */
    bool selected[256]; /* max update_queue_size */
    uint32_t sel_cap = sw->update_count < 256 ? sw->update_count : 256;
    memset(selected, 0, sel_cap * sizeof(bool));

    uint32_t written = 0;
    for (uint32_t p = 0; p < pick; p++) {
        int best = -1;
        uint16_t best_pb = UINT16_MAX;

        for (uint32_t i = 0; i < sel_cap; i++) {
            if (selected[i])
                continue;
            if (sw->updates[i].piggyback_count < best_pb) {
                best_pb = sw->updates[i].piggyback_count;
                best = (int)i;
            }
        }

        if (best < 0)
            break;

        out[written++] = sw->updates[best];
        sw->updates[best].piggyback_count++;
        sw->updates_piggybacked++;
        selected[best] = true;
    }

    /*
     * Prune over-disseminated updates: remove if piggyback_count >= limit.
     * Limit = 3 * log2(max(2, alive_count + 1))
     */
    uint32_t n = sw->alive_count > 2 ? sw->alive_count : 2;
    uint32_t limit = 3 * ilog2(n);
    if (limit < 3)
        limit = 3;

    uint32_t dst = 0;
    for (uint32_t src = 0; src < sw->update_count; src++) {
        if (sw->updates[src].piggyback_count >= (uint16_t)limit)
            continue;
        if (dst != src) {
            sw->updates[dst] = sw->updates[src];
        }
        dst++;
    }
    sw->update_count = dst;

    return written;
}

/* --------------------------------------------------------------------------
 * Iteration and statistics
 * -------------------------------------------------------------------------- */

uint32_t
wake_swim_iterate(const wake_swim_t *sw,
                   wake_swim_iter_fn fn, void *ctx)
{
    if (!sw || !fn)
        return 0;

    uint32_t count = 0;
    for (uint32_t i = 0; i < sw->member_count; i++) {
        count++;
        if (!fn(&sw->members[i], ctx))
            break;
    }
    return count;
}

void
wake_swim_stats(const wake_swim_t *sw, wake_swim_stats_t *out)
{
    if (!out)
        return;
    memset(out, 0, sizeof(*out));
    if (!sw)
        return;

    for (uint32_t i = 0; i < sw->member_count; i++) {
        out->total++;
        switch (sw->members[i].state) {
        case WAKE_SWIM_ALIVE:   out->alive++;   break;
        case WAKE_SWIM_SUSPECT: out->suspect++; break;
        case WAKE_SWIM_DEAD:    out->dead++;    break;
        case WAKE_SWIM_LEFT:    out->left++;    break;
        default: break;
        }
    }
    out->probe_eligible = out->alive + out->suspect;

    out->rounds_completed     = sw->rounds_completed;
    out->state_changes        = sw->state_changes;
    out->updates_queued       = sw->updates_queued;
    out->updates_piggybacked  = sw->updates_piggybacked;
    out->suspects_expired     = sw->suspects_expired;
}

/* --------------------------------------------------------------------------
 * Name accessors
 * -------------------------------------------------------------------------- */

static const char *state_names[] = {
    "ALIVE", "SUSPECT", "DEAD", "LEFT"
};

static const char *result_names[] = {
    "OK", "EXISTS", "NOT_FOUND", "FULL", "SELF", "STALE", "NOOP"
};

const char *
wake_swim_state_name(wake_swim_state_t s)
{
    if ((unsigned)s < WAKE_SWIM__COUNT)
        return state_names[(unsigned)s];
    return "UNKNOWN";
}

const char *
wake_swim_result_name(wake_swim_result_t r)
{
    if ((unsigned)r <= 6)
        return result_names[(unsigned)r];
    return "UNKNOWN";
}
