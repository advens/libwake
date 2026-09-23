/*
 * wake_swim.h: WAKE SWIM Membership Protocol
 *
 * Scalable Weakly-consistent Infection-style Membership (SWIM) protocol
 * for the WAKE mesh. Manages node membership, failure detection, and
 * state dissemination through piggybacked gossip updates.
 *
 * Bio-inspiration: SWIM is itself bio-inspired; infection-style
 * dissemination mimics pathogen spread. Combined with WAKE's pheromone
 * model: the membership layer is the nervous system (fast, point-to-point
 * failure detection), while pheromone signals are the hormonal system
 * (slower, broadcast threat awareness).
 *
 * Key design choices:
 *
 *   - Event-driven with injected time (now_ms parameter everywhere).
 *     No internal clocks. Fully testable, deterministic with fixed seed.
 *
 *   - Incarnation-based state machine (from SWIM paper):
 *     LEFT beats every other state at any incarnation. Otherwise a higher
 *     incarnation wins, and at the same incarnation DEAD > SUSPECT > ALIVE.
 *     A suspected node refutes by incrementing its own incarnation.
 *
 *   - Fisher-Yates probe ordering: each round shuffles the member list,
 *     ensuring every member is probed exactly once before any repeat.
 *     Better failure detection bounds than random selection.
 *
 *   - Dissemination via piggybacked updates: state changes are queued
 *     and attached to protocol messages. Priority by piggyback count
 *     (newest first). Automatic pruning after O(log N) disseminations.
 *
 *   - SplitMix64 PRNG: fast, well-distributed, deterministic with seed.
 *     Used for Fisher-Yates shuffle and delegate selection.
 *
 *   - Local Health Multiplier (Lifeguard-style): a caller-reported, bounded
 *     self-health score widens this node's own suspicion timeout under
 *     self-detected overload, so a temporarily slow node doesn't falsely
 *     accuse healthy peers. See wake_swim_report_health() below.
 *
 * Network I/O is NOT in this module; it provides the state machine.
 * The host application performs the actual ping/ack/indirect-ping over UDP.
 *
 * Scale: the member list is a dense array holding a FULL view of the mesh
 * (default max_members=512, calibrated for ~450 nodes). Every node tracks
 * every other node; there is no partial-view / peer-sampling layer. This
 * is the right tradeoff up to roughly O(100)-O(1000) nodes; it is also
 * exactly what lets wake_plumtree.h build its broadcast tree directly over
 * this membership without a separate overlay service. Deployments needing
 * a substantially larger mesh should pair this library with a partial-view
 * peer-sampling service (e.g. HyParView, the pairing PlumTree's own
 * research lineage uses at that scale) rather than growing max_members
 * further; this library does not provide that layer.
 *
 * Copyright (c) 2026 Advens. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef WAKE_SWIM_H
#define WAKE_SWIM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* --------------------------------------------------------------------------
 * Constants
 * -------------------------------------------------------------------------- */

/* Node ID is an Ed25519 public key (32 bytes) */
#define WAKE_SWIM_NODE_ID_LEN  32

/* --------------------------------------------------------------------------
 * Member states (ascending severity for same-incarnation precedence)
 * -------------------------------------------------------------------------- */
typedef enum {
    WAKE_SWIM_ALIVE   = 0,  /* Healthy, responding to probes             */
    WAKE_SWIM_SUSPECT = 1,  /* Failed direct probe, awaiting indirect    */
    WAKE_SWIM_DEAD    = 2,  /* Confirmed unreachable, pending reap       */
    WAKE_SWIM_LEFT    = 3,  /* Graceful departure (voluntary leave)      */
    WAKE_SWIM__COUNT  = 4
} wake_swim_state_t;

/* --------------------------------------------------------------------------
 * Operation results
 * -------------------------------------------------------------------------- */
typedef enum {
    WAKE_SWIM_OK        = 0,  /* Success                                */
    WAKE_SWIM_EXISTS    = 1,  /* Member already in list                 */
    WAKE_SWIM_NOT_FOUND = 2,  /* Member not in list                     */
    WAKE_SWIM_FULL      = 3,  /* Member list at capacity                */
    WAKE_SWIM_SELF      = 4,  /* Cannot operate on self                 */
    WAKE_SWIM_STALE     = 5,  /* Update has stale incarnation           */
    WAKE_SWIM_NOOP      = 6,  /* Update matches current state (no-op)   */
} wake_swim_result_t;

/* --------------------------------------------------------------------------
 * Member entry: 64 bytes.
 *
 * Each member in the list occupies exactly 64 bytes. The node_id is
 * the Ed25519 public key, the unique, unforgeable identity. 64 bytes is
 * one hardware cache line only where the line size is 64.
 * -------------------------------------------------------------------------- */
typedef struct {
    uint8_t  node_id[WAKE_SWIM_NODE_ID_LEN]; /* 32B: Ed25519 public key     */
    uint64_t last_change_ms; /*  8B: timestamp of last state change          */
    uint64_t suspect_ms;     /*  8B: when suspicion began (0 = not suspect)  */
    uint32_t addr;           /*  4B: IPv4 address (network byte order)       */
    uint32_t incarnation;    /*  4B: incarnation number (monotonic)           */
    uint16_t port;           /*  2B: port (network byte order)               */
    uint8_t  state;          /*  1B: wake_swim_state_t                       */
    uint8_t  _reserved[5];   /*  5B: pad to 64 bytes                         */
} wake_swim_member_t;

_Static_assert(sizeof(wake_swim_member_t) == 64,
    "swim member must be exactly 64 bytes");

/* --------------------------------------------------------------------------
 * Dissemination update: 48 bytes
 *
 * Piggybacked onto protocol messages (ping, ack, indirect-ping).
 * Carries a state change that should be disseminated to peers.
 *
 * piggyback_count tracks how many times this update has been sent.
 * Updates with lower count are prioritized (newer information first).
 * Pruned after count exceeds dissemination limit (~3 * log2(N)).
 * -------------------------------------------------------------------------- */
typedef struct {
    uint8_t  node_id[WAKE_SWIM_NODE_ID_LEN]; /* 32B: subject of the update  */
    uint32_t addr;           /*  4B: IPv4 address                            */
    uint16_t port;           /*  2B: port                                    */
    uint8_t  state;          /*  1B: wake_swim_state_t                       */
    uint8_t  _pad0;          /*  1B: alignment                               */
    uint32_t incarnation;    /*  4B: incarnation number                      */
    uint16_t piggyback_count;/*  2B: times piggybacked so far                */
    uint16_t _pad1;          /*  2B: pad to 48 bytes                         */
} wake_swim_update_t;

_Static_assert(sizeof(wake_swim_update_t) == 48,
    "swim update must be exactly 48 bytes");

/* --------------------------------------------------------------------------
 * Configuration: 32 bytes
 *
 * All timing uses milliseconds. protocol_period_ms is the fundamental
 * heartbeat: one probe per period. Suspicion timeout scales with group
 * size: suspicion_mult * floor(log2(N)) * protocol_period_ms, then times
 * (1 + health_score).
 *
 * Default values tuned for about 450 alive members:
 *   protocol_period_ms=1000, one probe per second
 *   suspicion_mult=5 gives 40s at 450 alive members when health_score is 0
 *   (floor log2), then times (1 + health_score).
 *   max_members=512, headroom above 450
 * -------------------------------------------------------------------------- */
typedef struct {
    uint16_t max_members;         /* Max members (default: 512)           */
    uint16_t update_queue_size;   /* Dissemination queue size (dflt: 256) */
    uint16_t suspicion_mult;      /* Suspicion timeout scale (default: 5) */
    uint16_t max_piggybacks;      /* Updates per message (default: 8)     */
    uint32_t protocol_period_ms;  /* Probe interval in ms (default: 1000) */
    uint32_t suspect_timeout_ms;  /* Fixed timeout (0 = auto from mult)   */
    uint64_t prng_seed;           /* PRNG seed (0 = use time-based)       */
    uint8_t  _reserved[8];
} wake_swim_config_t;

_Static_assert(sizeof(wake_swim_config_t) == 32,
    "swim config must be exactly 32 bytes");

/* --------------------------------------------------------------------------
 * Statistics snapshot
 * -------------------------------------------------------------------------- */
typedef struct {
    uint32_t total;          /* Total members in list                      */
    uint32_t alive;          /* Members in ALIVE state                     */
    uint32_t suspect;        /* Members in SUSPECT state                   */
    uint32_t dead;           /* Members in DEAD state                      */
    uint32_t left;           /* Members in LEFT state                      */
    uint32_t probe_eligible; /* ALIVE + SUSPECT (probe targets)            */
    /* Lifetime counters */
    uint64_t rounds_completed;
    uint64_t state_changes;
    uint64_t updates_queued;
    uint64_t updates_piggybacked;
    uint64_t suspects_expired;
} wake_swim_stats_t;

/* --------------------------------------------------------------------------
 * Main SWIM state (owned by the host application, single-threaded)
 * -------------------------------------------------------------------------- */
typedef struct {
    wake_swim_config_t   config;

    /* Member list (dense array, all states) */
    wake_swim_member_t  *members;
    uint32_t             member_count;    /* Total entries */
    uint32_t             alive_count;     /* ALIVE + SUSPECT (probe-eligible) */

    /* Probe ordering (Fisher-Yates) */
    uint32_t            *probe_order;     /* [max_members] shuffled indices */
    uint32_t             probe_size;      /* Entries in current probe order */
    uint32_t             probe_index;     /* Next index to probe */

    /* Dissemination queue (priority by piggyback_count) */
    wake_swim_update_t  *updates;         /* [update_queue_size] */
    uint32_t             update_count;    /* Current queued updates */

    /* Self identity */
    uint8_t              self_id[WAKE_SWIM_NODE_ID_LEN];
    uint32_t             self_addr;
    uint16_t             self_port;
    uint16_t             _pad0;
    uint32_t             self_incarnation;
    uint32_t             _pad1;

    /* PRNG state (SplitMix64) */
    uint64_t             prng_state;

    /* Lifetime counters */
    uint64_t             rounds_completed;
    uint64_t             state_changes;
    uint64_t             updates_queued;
    uint64_t             updates_piggybacked;
    uint64_t             suspects_expired;

    /* Local Health Multiplier (see wake_swim_report_health below). Appended
     * as the last field deliberately: wake_swim_t is internal runtime state,
     * not a wire/cache-line struct (no _Static_assert on its size), so this
     * is a safe, layout-stable place to extend it. */
    uint32_t             health_score;
} wake_swim_t;

/* --------------------------------------------------------------------------
 * Configuration
 * -------------------------------------------------------------------------- */

/* Returns config with production-calibrated defaults. */
wake_swim_config_t wake_swim_default_config(void);

/* --------------------------------------------------------------------------
 * Lifecycle
 * -------------------------------------------------------------------------- */

/*
 * Create a SWIM instance with the given self identity.
 *
 * self_id: this node's Ed25519 public key (32 bytes).
 * self_addr/self_port: this node's network address.
 * cfg: configuration (NULL for defaults).
 *
 * Returns NULL on allocation failure.
 */
wake_swim_t *wake_swim_create(const uint8_t self_id[WAKE_SWIM_NODE_ID_LEN],
                               uint32_t self_addr, uint16_t self_port,
                               const wake_swim_config_t *cfg);

/* Destroy and free all resources. */
void wake_swim_destroy(wake_swim_t *sw);

/* Reset all members and counters. Keeps config and self identity. */
void wake_swim_reset(wake_swim_t *sw);

/* --------------------------------------------------------------------------
 * Member management
 * -------------------------------------------------------------------------- */

/*
 * Add a new member in ALIVE state.
 * Queues an ALIVE update for dissemination.
 *
 * Returns:
 *   WAKE_SWIM_OK: added successfully
 *   WAKE_SWIM_EXISTS: already in list (not modified)
 *   WAKE_SWIM_FULL: member list at capacity
 *   WAKE_SWIM_SELF: node_id matches self
 */
wake_swim_result_t wake_swim_add_member(wake_swim_t *sw,
                                         const uint8_t node_id[WAKE_SWIM_NODE_ID_LEN],
                                         uint32_t addr, uint16_t port,
                                         uint64_t now_ms);

/*
 * Mark a member as LEFT (graceful departure).
 * Queues a LEFT update for dissemination.
 *
 * Returns:
 *   WAKE_SWIM_OK: marked as LEFT
 *   WAKE_SWIM_NOT_FOUND: not in list
 *   WAKE_SWIM_SELF: cannot remove self
 */
wake_swim_result_t wake_swim_remove_member(wake_swim_t *sw,
                                            const uint8_t node_id[WAKE_SWIM_NODE_ID_LEN],
                                            uint64_t now_ms);

/*
 * Find a member by node_id.
 * Returns pointer to internal entry (valid until next mutation), or NULL.
 */
const wake_swim_member_t *wake_swim_find(const wake_swim_t *sw,
                                          const uint8_t node_id[WAKE_SWIM_NODE_ID_LEN]);

/* --------------------------------------------------------------------------
 * State machine: incarnation-based updates
 *
 * Implements SWIM state precedence:
 *   - Higher incarnation always wins
 *   - Same incarnation: DEAD > SUSPECT > ALIVE
 *   - LEFT always wins (regardless of incarnation)
 *
 * If the update targets self and is a SUSPECT/DEAD state,
 * self-refutation is triggered: self_incarnation is incremented
 * and an ALIVE update is queued for dissemination.
 * -------------------------------------------------------------------------- */

/*
 * Apply a state update received from a peer.
 * Handles incarnation precedence, self-refutation, and dissemination.
 *
 * Returns:
 *   WAKE_SWIM_OK: state changed
 *   WAKE_SWIM_STALE: update has stale incarnation
 *   WAKE_SWIM_NOOP: update matches current state
 *   WAKE_SWIM_NOT_FOUND: unknown member (added if state is ALIVE)
 *   WAKE_SWIM_FULL: cannot add (member list full)
 */
wake_swim_result_t wake_swim_apply_update(wake_swim_t *sw,
                                           const wake_swim_update_t *update,
                                           uint64_t now_ms);

/*
 * Mark a member as SUSPECT (probe failure).
 * Only transitions ALIVE → SUSPECT. No-op if already SUSPECT/DEAD/LEFT.
 * Queues a SUSPECT update for dissemination.
 *
 * Returns:
 *   WAKE_SWIM_OK: marked as SUSPECT
 *   WAKE_SWIM_STALE: already SUSPECT, DEAD, or LEFT
 *   WAKE_SWIM_NOT_FOUND: not in list
 *   WAKE_SWIM_SELF: cannot suspect self
 */
wake_swim_result_t wake_swim_suspect_member(wake_swim_t *sw,
                                             const uint8_t node_id[WAKE_SWIM_NODE_ID_LEN],
                                             uint64_t now_ms);

/* --------------------------------------------------------------------------
 * Protocol actions (called by the host application's protocol loop)
 * -------------------------------------------------------------------------- */

/*
 * Get the next probe target using Fisher-Yates ordering.
 *
 * Returns the member to probe, or NULL if no eligible members.
 * When all members have been probed in the current round,
 * automatically reshuffles and starts a new round.
 *
 * Only returns ALIVE or SUSPECT members.
 */
const wake_swim_member_t *wake_swim_next_probe(wake_swim_t *sw);

/*
 * Select up to `max` random ALIVE members for indirect probing,
 * excluding `exclude_id` (the suspected target).
 *
 * Writes selected members to `out[]` array.
 * Returns the number of delegates selected.
 */
uint32_t wake_swim_select_delegates(wake_swim_t *sw,
                                     const uint8_t exclude_id[WAKE_SWIM_NODE_ID_LEN],
                                     wake_swim_member_t *out,
                                     uint32_t max);

/* --------------------------------------------------------------------------
 * Suspicion management
 * -------------------------------------------------------------------------- */

/*
 * Calculate the current suspicion timeout based on group size.
 * Uses: suspicion_mult * floor(log2(max(2, alive_count))) * protocol_period_ms
 *
 * If config.suspect_timeout_ms is non-zero, that value is the base instead
 * of the formula above. Either way, the result is then scaled by
 * (1 + wake_swim_health(sw)); see wake_swim_report_health below.
 */
uint32_t wake_swim_suspect_timeout(const wake_swim_t *sw);

/* --------------------------------------------------------------------------
 * Local Health Multiplier (Lifeguard-style situational awareness)
 *
 * Reference: Hashicorp, "Lifeguard: SWIM-ing with Situational Awareness"
 * (2018), the extension HashiCorp added to memberlist/Serf/Consul's SWIM
 * after production experience: a node under its own CPU/scheduler/network
 * load can miss its own timing deadlines and, from that alone, wrongly
 * accuse perfectly healthy peers of having failed. The fix keeps a small,
 * bounded, PURELY LOCAL health score (never gossiped, never compared across
 * nodes) that widens this node's own suspicion timeout when it can't trust
 * its own timing, and narrows back to baseline as it recovers.
 *
 * This module does not observe scheduling delay itself; it has no access to
 * the caller's event loop or timers (by design: no internal clocks, see the
 * file header). The CALLER reports health-affecting events as they happen:
 * a probe round that overran protocol_period_ms is unhealthy (+1); a round
 * that completed within budget is healthy (-1). The score is clamped to
 * [0, WAKE_SWIM_HEALTH_MAX]; it can only ever slow this node down relative
 * to baseline, never speed it up, matching the Lifeguard paper's own bound.
 * -------------------------------------------------------------------------- */

#define WAKE_SWIM_HEALTH_MAX 8u

/*
 * Report a health-affecting event. Positive delta = degraded (e.g. this
 * node's own protocol tick overran its budget); negative delta = recovered
 * (e.g. a tick completed cleanly). Clamped to [0, WAKE_SWIM_HEALTH_MAX].
 */
void wake_swim_report_health(wake_swim_t *sw, int delta);

/* Current health score. 0 means the timeout is the unscaled baseline. */
uint32_t wake_swim_health(const wake_swim_t *sw);

/*
 * Check all SUSPECT members and expire those whose suspicion
 * has exceeded the timeout. Expired members transition to DEAD.
 *
 * Returns the number of members expired to DEAD.
 */
uint32_t wake_swim_check_suspects(wake_swim_t *sw, uint64_t now_ms);

/*
 * Reap DEAD and LEFT members that have been in terminal state
 * for longer than `retention_ms`. Compacts the member array.
 *
 * Returns the number of entries reaped.
 */
uint32_t wake_swim_reap(wake_swim_t *sw, uint64_t now_ms,
                          uint64_t retention_ms);

/* --------------------------------------------------------------------------
 * Dissemination queue
 * -------------------------------------------------------------------------- */

/*
 * Get up to `max` updates for piggybacking onto a protocol message.
 * Returns updates ordered by priority (lowest piggyback_count first).
 * Increments piggyback_count for each returned update.
 * Prunes updates that have been sent enough times (>= 3 * log2(N)).
 *
 * Returns the number of updates written to `out[]`.
 */
uint32_t wake_swim_get_updates(wake_swim_t *sw,
                                wake_swim_update_t *out,
                                uint32_t max);

/* --------------------------------------------------------------------------
 * Iteration and statistics
 * -------------------------------------------------------------------------- */

/* Iterate all members. Return false from callback to stop. */
typedef bool (*wake_swim_iter_fn)(const wake_swim_member_t *m, void *ctx);

uint32_t wake_swim_iterate(const wake_swim_t *sw,
                            wake_swim_iter_fn fn, void *ctx);

/* Collect statistics snapshot. */
void wake_swim_stats(const wake_swim_t *sw, wake_swim_stats_t *out);

/* --------------------------------------------------------------------------
 * Name accessors
 * -------------------------------------------------------------------------- */

const char *wake_swim_state_name(wake_swim_state_t s);
const char *wake_swim_result_name(wake_swim_result_t r);

/* --------------------------------------------------------------------------
 * Internal: SplitMix64 PRNG (exposed for testing)
 * -------------------------------------------------------------------------- */

static inline uint64_t
wake_splitmix64(uint64_t *state)
{
    uint64_t z = (*state += UINT64_C(0x9E3779B97F4A7C15));
    z = (z ^ (z >> 30)) * UINT64_C(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94D049BB133111EB);
    return z ^ (z >> 31);
}

#ifdef __cplusplus
}
#endif

#endif /* WAKE_SWIM_H */
