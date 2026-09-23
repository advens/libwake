/*
 * wake_tac.h: WAKE Transient Associative Coupling table
 *
 * A decaying co-activation memory over interpretation hypotheses. Each node is
 * a (technique, entity) pair; each edge is an undirected, decaying coupling
 * between two techniques observed together on the same entity. An external
 * query reads the (activation, coupling) landscape; the table never emits a
 * verdict of its own.
 *
 * Relationship to the pheromone table:
 *   - wake_pheromone_t holds per-ENTITY confidence. It is an activation input
 *     to this table, not replaced by it.
 *   - wake_tac_t holds per-ENTITY couplings between TECHNIQUES. It is a third,
 *     separate structure. It shares the pheromone concurrency recipe (open
 *     addressing, CAS slot claim, version-guarded identity bytes, fixed-point decay, mmap)
 *     but not its layout, its file, its decay rate, or its hash key.
 *
 * Hashing:
 *   - This table owns its SipHash key (header->hash_key). It NEVER installs a
 *     process-global key: wake_hash_set_key() and wake_entity_hash() belong to
 *     the pheromone/entity path, and a host application typically runs both in one process. All TAC
 *     hashing goes through the keyed helper wake_hash_bytes_keyed().
 *
 * Design:
 *   - Counters on cache line 0 are atomic; budget[] is plain memory and
 *     is read only by the single writer
 *   - 128-byte entries: coupling state in the first 64 bytes, entity
 *     identity in the next 64
 *   - Open addressing, bounded linear probing (WAKE_TAC_PROBE_MAX)
 *   - entity_hash is atomic; the 56-byte ident copy is written under
 *     version and is not read concurrently
 *   - mmap-backed, mapped by ONE process (the host application). There is no cross-process
 *     consumer in this release: any UI reaches the table by RPC into the
 *     host application, which serves wake_tac_query from its own mapping. The concurrency
 *     model below is therefore intra-process (single writer vs reader
 *     threads), and a second mapping is out of contract.
 *   - Two-rate decay: a fast rate for uncorroborated edges, a slow rate once an
 *     edge has been reinforced by independent, sufficiently confident sources.
 *
 * Scope:
 *   - Writes come only from the single writer. Aggregation-entity exclusion,
 *     remote-contribution eligibility, and the fidelity -> eta mapping are
 *     applied by the caller before reinforce.
 *   - No mesh: this translation unit references no SWIM, PlumTree, signal,
 *     crypto-signing, or quorum symbol.
 *
 * Memory layout (mmap'd file):
 *   [0..255]                       wake_tac_header_t
 *   [256 .. 256 + N*128)           wake_tac_entry_t[capacity]
 *   [256 + N*128 ..]               wake_tac_occ_t[occ_slots]   (occupancy sidecar)
 *
 * Both supported architectures (aarch64, amd64) are little-endian; the mmap'd
 * integer fields are stored native and are byte-identical across them.
 *
 * Copyright (c) 2026 Advens. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef WAKE_TAC_H
#define WAKE_TAC_H

#include "wake_entity.h"   /* wake_hash_bytes_keyed() */

#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* --------------------------------------------------------------------------
 * Constants
 * -------------------------------------------------------------------------- */

/* Maximum linear probe distance for the main table. */
#define WAKE_TAC_PROBE_MAX   8

/* Probe distance for the occupancy sidecar. Larger than the main table's: the
 * sidecar sizing guarantee (occ_slots >= capacity) keeps its load factor at or
 * below the main table's, and a failed occ claim fails CLOSED (the new edge is
 * refused, never inserted uncapped), so a deeper probe just makes that rare. */
#define WAKE_TAC_OCC_PROBE_MAX   16

/* Upper bound on the entry count (a corrupted header must not drive a
 * multi-hundred-GB mmap). 2^24 entries = 2 GiB main table. */
#define WAKE_TAC_MAX_CAPACITY   (1u << 24)

/* Slot state sentinels (a computed key_hash equal to one of these is nudged). */
#define WAKE_TAC_SLOT_EMPTY      UINT64_C(0)
#define WAKE_TAC_SLOT_TOMBSTONE  UINT64_C(0xDEADDEADDEADDEAD)

/* Defaults (all overridable via wake_tac_config_t). */
#define WAKE_TAC_DEFAULT_CAPACITY        65536u  /* entries, 8 MiB              */
/* Occupancy sidecar slot count. cfg->occ_slots == 0 resolves to `capacity`
 * (not this constant): the sidecar must be able to hold every entity that
 * could have a live edge, so occ_slots < capacity is rejected. */
#define WAKE_TAC_DEFAULT_OCC_SLOTS      65536u  /* == default capacity         */
#define WAKE_TAC_DEFAULT_DECAY_NOVEL_FP16 62576u /* ~15 min half-life @ 60 s    */
#define WAKE_TAC_DEFAULT_DECAY_CORR_FP16  65504u /* ~24 h half-life @ 60 s      */
#define WAKE_TAC_DEFAULT_NOISE_FLOOR      1000u  /* weight below this = dead    */
#define WAKE_TAC_DEFAULT_PER_ENTITY_CAP     32u  /* live edges per entity       */
#define WAKE_TAC_PER_ENTITY_CAP_MAX         32u  /* sidecar slot-index capacity */
#define WAKE_TAC_DEFAULT_CORROBORATION_MIN   2u  /* distinct sources            */
#define WAKE_TAC_DEFAULT_BUDGET_PER_SOURCE 20000u /* force units, <= UINT16_MAX */
#define WAKE_TAC_DEFAULT_TICK_SECONDS        60u /* seconds between decay ticks */

/* An edge earns the slow (corroborated) decay rate only when it has been
 * reinforced by at least corroboration_src_min distinct sources AND at least
 * one of them was STRONG tier or higher (eta_max_fp16 >= this). Two
 * low-confidence sources co-firing never earns slow decay. */
#define WAKE_TAC_ETA_STRONG_FP16  39321u   /* 0.60 in 0.16 fixed point */

/* Reinforcement force delta derived from the fidelity weight:
 *   CONFIRMED 1.0 -> 4095,  STRONG 0.6 -> 2457,  WEAK 0.3 -> 1228,  CONTEXT 0.1 -> 409
 * `weight` and each budget slot's `spent` accumulate this delta in the same
 * "force units". Decay never refunds `spent`. The scale is chosen so a
 * corroborated edge settles in the thousands, where the 0.16 fixed-point decay
 * factor is accurate (below ~2000 the per-tick truncation floor dominates and
 * the half-life collapses). */
#define WAKE_TAC_DELTA(eta_fp16)  ((uint32_t)(uint16_t)(eta_fp16) >> 4)
#define WAKE_TAC_DELTA_MAX        4095u   /* WAKE_TAC_DELTA(0xFFFF); a valid
                                          * budget_per_source is >= this */

/* Per-source budget slots in an entry: WAKE_TAC_BUDGET_NAMED slots keyed by a
 * real source_id, plus one shared overflow bucket (index
 * WAKE_TAC_BUDGET_NAMED) that absorbs the 5th and every further distinct
 * source.
 *
 * src_count saturates at WAKE_TAC_BUDGET_SLOTS, and that ceiling is a security
 * property, not an accounting shortcut: only the named slots carry a source
 * identity, so past the overflow bucket the table CANNOT distinguish a genuine
 * 6th witness from the 5th one hitting again. Counting those as new witnesses
 * would let a single producer inflate its own corroboration and buy the slow
 * decay rate alone; the single-source forgery this gate exists to stop.
 * The gate only needs corroboration_src_min (2) distinct sources; beyond
 * the 5 the table can prove, extra witnesses add no trust it can defend. */
#define WAKE_TAC_BUDGET_NAMED   4
#define WAKE_TAC_BUDGET_SLOTS   (WAKE_TAC_BUDGET_NAMED + 1)   /* == 5 */
#define WAKE_TAC_SRC_NONE       0u          /* empty slot / invalid source id  */
#define WAKE_TAC_SRC_OTHER      0xFFFFu     /* shared overflow bucket           */

/* Outlier-reinforcement quarantine. An edge whose weight is dominated by a
 * SINGLE source past a floor is a candidate forgery: one producer, sustained,
 * manufacturing a coupling on its own. Such an edge is quarantined: excluded
 * from query/route mass and refused further reinforcement FROM THE SOURCES IT
 * ALREADY CARRIES, while still decaying normally. A genuinely new distinct
 * source clears it: independent corroboration is the evidence quarantine waits
 * for, so the mechanism can never bury a real multi-witness campaign. */
#define WAKE_TAC_QUARANTINE_SHARE_PCT  80u   /* one source holds >= this % of w */
#define WAKE_TAC_DEFAULT_QUARANTINE_MIN_W  4000u /* and w >= this (4x floor)    */

/* Identity blob capacity in the cold line. Entity keys longer than this are
 * stored truncated with WAKE_TAC_IDENT_HASHED set; the readable key is
 * recovered by the caller, which holds the original string. `entity_hash`
 * (the sidecar / scan key) is always exact regardless of truncation. */
#define WAKE_TAC_IDENT_MAX     54
#define WAKE_TAC_IDENT_HASHED  0x01u

/* Packed technique (uint32, stored native / little-endian):
 *   bits  0..15  base    ATT&CK technique number       (0 .. 65535)
 *   bits 16..23  sub      sub-technique number          (0 .. 255)
 *   bits 24..31  flags    WAKE_TAC_TECH_*               (0 .. 255)
 *   packed = (uint32_t)base | ((uint32_t)sub << 16) | ((uint32_t)flags << 24)
 * A numeric compare canonicalizes an undirected pair; HASHED labels (flags
 * bit set) therefore sort after every real technique, deterministically.
 * Every binding must use these accessors, never open-coded shifts. */
#define WAKE_TAC_TECH_HASHED     0x01u
#define WAKE_TAC_TECH_BASE(p)    ((uint16_t)((uint32_t)(p) & 0xFFFFu))
#define WAKE_TAC_TECH_SUB(p)     ((uint8_t)(((uint32_t)(p) >> 16) & 0xFFu))
#define WAKE_TAC_TECH_FLAGS(p)   ((uint8_t)(((uint32_t)(p) >> 24) & 0xFFu))

/* Max edges returned in a query snapshot, independent of the runtime cap. */
#define WAKE_TAC_QUERY_TOP_MAX  32

/* Header magic: "WAKETAC\0" as a little-endian uint64. */
#define WAKE_TAC_MAGIC    UINT64_C(0x00434154454B4157)
#define WAKE_TAC_VERSION  1

/* --------------------------------------------------------------------------
 * Entry: 128 bytes (two 64-byte groups). 64 bytes is one hardware cache
 * line only where the line size is 64.
 *
 * Cache line 0 (0..63): coupling state. Counters are atomic; budget[] is
 *   plain memory and is read only by the single writer. t_lo/t_hi are
 *   written before the key_hash CAS that publishes the slot and are
 *   immutable for that slot generation; a reader that observes a live
 *   key_hash (acquire) observes the pair.
 * Cache line 1 (64..127): entity identity.
 *   `entity_hash` (keyed hash of the full entity_key) is `_Atomic` and is the
 *   exact match key for the occupancy sidecar and for query/route/read_entry.
 *   `ident_len` / `ident_flags` / `ident[]` are a plain (non-atomic) display
 *   copy of the leading key bytes, written under the `version` seqlock. NO
 *   concurrent reader touches them (`wake_tac_read_entry` leaves them zeroed);
 *   they are only for an offline, quiescent dump. The caller recovers the
 *   readable key from `entity_hash` via its own reverse map.
 * -------------------------------------------------------------------------- */
typedef struct {
    uint16_t source_id;   /* stable 16-bit producer id, or WAKE_TAC_SRC_*  */
    uint16_t spent;       /* force already charged to this source          */
} wake_tac_budget_t;

_Static_assert(sizeof(wake_tac_budget_t) == 4, "budget slot must be 4 bytes");

typedef struct {
    /* --- Cache line 0: coupling state (offsets 0..63) --- */
    _Atomic uint64_t key_hash;      /*  0  8B: slot state + edge identity     */
    _Atomic uint32_t weight;        /*  8  4B: accumulated coupling force (w) */
    _Atomic uint32_t reinf_count;   /* 12  4B: total reinforcements           */
    _Atomic uint32_t last_reinf;    /* 16  4B: seconds since table epoch      */
    _Atomic uint32_t first_seen;    /* 20  4B: seconds since table epoch      */
    _Atomic uint32_t version;       /* 24  4B: seqlock for the identity blob  */
    _Atomic uint32_t t_lo;          /* 28  4B: packed technique, canonical lo */
    _Atomic uint32_t t_hi;          /* 32  4B: packed technique, canonical hi */
    _Atomic uint16_t eta_max_fp16;  /* 36  2B: highest source eta seen        */
    _Atomic uint8_t  src_count;     /* 38  1B: distinct sources, saturating at
                                     *         WAKE_TAC_BUDGET_SLOTS; see the
                                     *         budget-slot note above: past the
                                     *         overflow bucket a new witness is
                                     *         indistinguishable from a repeat */
    _Atomic uint8_t  quarantine;    /* 39  1B: nonzero = excluded from mass   */
    wake_tac_budget_t budget[WAKE_TAC_BUDGET_SLOTS]; /* 40 20B                */
    uint8_t          _pad0[4];      /* 60  4B: pad cache line 0 to 64         */

    /* --- Cache line 1: entity identity (offsets 64..127) --- */
    _Atomic uint64_t entity_hash;  /* 64  8B: keyed hash of the full key;
                                    *         atomic so query/route can filter
                                    *         without the seqlock              */
    uint8_t  ident_len;            /* 72  1B: bytes of the key stored below;
                                    *         ident_len/flags/ident[] are
                                    *         seqlock-protected via `version`   */
    uint8_t  ident_flags;          /* 73  1B: WAKE_TAC_IDENT_HASHED           */
    uint8_t  ident[WAKE_TAC_IDENT_MAX]; /* 74 54B: leading key bytes (display)*/
} __attribute__((aligned(128))) wake_tac_entry_t;

_Static_assert(sizeof(wake_tac_entry_t) == 128,
    "TAC entry must be exactly 128 bytes");
_Static_assert(offsetof(wake_tac_entry_t, entity_hash) == 64,
    "identity must start at byte 64");

/* --------------------------------------------------------------------------
 * Occupancy sidecar entry: 144 bytes
 *
 * Per-entity edge index: the live edge count AND the entry slots holding those
 * edges. Both the cap check and the weakest-edge search for cap eviction are
 * therefore O(per_entity_cap), never a scan of the whole table; an entity
 * being flooded with distinct pairs must not cost the writer a
 * capacity-sized scan per pair (that would BE the eviction-DoS).
 *
 * Sizing: occ_slots >= capacity (enforced in create/open), so the sidecar can
 * hold every entity that could have a live edge and its load factor never
 * exceeds the main table's. If a claim still fails the 16-probe window, the
 * new edge is REFUSED (fail closed); it is never inserted uncapped.
 *
 * Rebuilt from the live entries on every decay pass.
 * -------------------------------------------------------------------------- */
typedef struct {
    _Atomic uint64_t entity_hash;   /*   8B: 0 = empty                       */
    _Atomic uint32_t live_count;    /*   4B: live edges for this entity      */
    uint32_t         _pad;          /*   4B                                  */
    _Atomic uint32_t slot[WAKE_TAC_PER_ENTITY_CAP_MAX];
                                    /* 128B: entry indices, live_count used  */
} wake_tac_occ_t;

_Static_assert(sizeof(wake_tac_occ_t) == 144,
    "occupancy slot must be 144 bytes");

/* --------------------------------------------------------------------------
 * Header: 256 bytes (mmap'd, at file offset 0)
 * -------------------------------------------------------------------------- */
typedef struct {
    uint64_t magic;                 /*   8B */
    uint32_t format_version;        /*   4B */
    uint32_t capacity;              /*   4B: entry slot count (power of 2)   */
    uint64_t mask;                  /*   8B: capacity - 1                    */
    uint8_t  hash_key[16];          /*  16B: SipHash key, owned by this table*/
    uint32_t epoch;                 /*   4B: Unix time at table creation     */
    uint32_t decay_novel_fp16;      /*   4B: 0.16 fixed point                */
    uint32_t decay_corr_fp16;       /*   4B: 0.16 fixed point                */
    uint32_t noise_floor;           /*   4B                                  */
    uint32_t occ_slots;             /*   4B: occupancy sidecar slot count    */
    uint32_t budget_per_source;     /*   4B: force units, <= UINT16_MAX      */
    uint16_t per_entity_cap;        /*   2B: <= WAKE_TAC_PER_ENTITY_CAP_MAX  */
    uint16_t corroboration_src_min; /*   2B                                  */
    uint32_t tick_seconds;          /*   4B: informational; caller drives decay */
    uint32_t quarantine_min_w;      /*   4B: outlier floor (0 = disabled)    */
    uint8_t  _reserved[180];        /* 180B: pad to 256                      */
} wake_tac_header_t;

_Static_assert(sizeof(wake_tac_header_t) == 256,
    "TAC header must be exactly 256 bytes");

/* --------------------------------------------------------------------------
 * Handles and value types
 * -------------------------------------------------------------------------- */
typedef struct {
    wake_tac_header_t *header;
    wake_tac_entry_t  *entries;
    wake_tac_occ_t    *occ;
    void              *map_base;
    size_t             map_size;
    int                fd;
} wake_tac_t;

typedef struct {
    uint32_t capacity;               /* pow2; 0 = default; <= MAX_CAPACITY   */
    uint32_t occ_slots;              /* pow2; 0 = capacity; must be >= capacity */
    uint32_t decay_novel_fp16;       /* 0 = default                          */
    uint32_t decay_corr_fp16;        /* 0 = default                          */
    uint32_t noise_floor;            /* 0 = default                          */
    uint32_t budget_per_source;      /* 0 = default; must be <= UINT16_MAX    */
    uint16_t per_entity_cap;         /* 0 = default; <= CAP_MAX              */
    uint16_t corroboration_src_min;  /* 0 = default                          */
    uint32_t tick_seconds;           /* 0 = default                          */
    uint32_t quarantine_min_w;       /* 0 = default; UINT32_MAX disables      */
} wake_tac_config_t;

/* One activation handed to reinforce/route: a technique fired on the entity
 * this cycle, with the fidelity-derived weight and the producing source. */
typedef struct {
    uint32_t technique;   /* packed; wake_tac_pack* + WAKE_TAC_TECH_* accessors */
    uint16_t eta_fp16;    /* fidelity tier weight, 0.16 fixed point             */
    uint16_t source_id;   /* stable producer id, never WAKE_TAC_SRC_NONE        */
} wake_tac_activation_t;

typedef struct {
    uint32_t t_lo;
    uint32_t t_hi;
    uint32_t weight;
    uint16_t eta_max_fp16;
    uint8_t  src_count;
    uint8_t  quarantine;
} wake_tac_edge_t;

typedef struct {
    uint32_t        coupling_mass;   /* sum of w over live, non-quarantined edges */
    uint32_t        edge_count;      /* live edges for this entity               */
    uint32_t        top_count;       /* entries filled in top[]                  */
    wake_tac_edge_t top[WAKE_TAC_QUERY_TOP_MAX];
    /* No verdict, no campaign, no kill_chain, no tier. The external caller
     * applies its own threshold. */
} wake_tac_snapshot_t;

typedef struct {
    uint32_t technique;   /* packed */
    uint32_t input_fp16;  /* routed activation contribution for this technique */
} wake_tac_input_t;

typedef struct {
    uint32_t capacity;
    uint32_t occupied;
    uint32_t tombstones;
    uint32_t entities_at_cap;
    uint32_t quarantined;
    uint32_t max_probe_len;
    uint64_t total_weight;
} wake_tac_stats_t;

/* reinforce / reinforce_batch per-pair outcome. */
typedef enum {
    WAKE_TAC_APPLIED            = 0,
    WAKE_TAC_REFUSED_CAP        = 1, /* entity at per_entity_cap, no weaker edge */
    WAKE_TAC_REFUSED_BUDGET     = 2, /* source has spent its budget              */
    WAKE_TAC_REFUSED_QUARANTINE = 3, /* edge is quarantined                      */
    WAKE_TAC_TABLE_FULL         = 4, /* no slot in probe range                   */
    WAKE_TAC_INVALID            = 5  /* empty key, self-pair, bad source_id      */
} wake_tac_result_t;

/* --------------------------------------------------------------------------
 * Lifecycle
 * -------------------------------------------------------------------------- */

/* Create a table backed by a fresh file at `path` (mode 0600, truncated).
 * Generates a random SipHash key, stored ONLY in header->hash_key; the
 * process-global key is never touched. Returns NULL on error (errno set). */
wake_tac_t *wake_tac_create(const char *path, const wake_tac_config_t *cfg);

/* Open an existing table. Validates magic/version. The SipHash key is read
 * from the header and used per-call; the process-global key is never touched.
 * Returns NULL on error (errno set). */
wake_tac_t *wake_tac_open(const char *path);

/* Unmap and close. The handle is invalid afterward. */
void wake_tac_close(wake_tac_t *t);

/* Discard every edge and the occupancy sidecar; keep the header and the
 * SipHash key. The caller must be quiescent. */
void wake_tac_reset(wake_tac_t *t);

/* --------------------------------------------------------------------------
 * Time
 * -------------------------------------------------------------------------- */

/* Seconds since this table's epoch, from CLOCK_REALTIME (same clock as the
 * pheromone epoch). Feeds only the bookkeeping fields last_reinf / first_seen;
 * decay is driven by call count, not by this value. Production callers pass
 * this as `now_rel`; tests pass their own monotonic counter. */
uint32_t wake_tac_now(const wake_tac_t *t);

/* --------------------------------------------------------------------------
 * Technique packing
 * -------------------------------------------------------------------------- */

/* Pack an ATT&CK technique. `sub` is 0 for a bare technique. */
uint32_t wake_tac_pack(uint16_t base, uint8_t sub);

/* Pack a non-ATT&CK label as a hashed technique (WAKE_TAC_TECH_HASHED set).
 * Uses a fixed internal key so the result is stable across processes. */
uint32_t wake_tac_pack_label(const char *label, size_t len);

/* --------------------------------------------------------------------------
 * Write path (single writer only)
 * -------------------------------------------------------------------------- */

/* Reinforce the single undirected edge (t_a, t_b) on `entity_key`.
 * The pair is canonicalized internally; a self-pair returns WAKE_TAC_INVALID.
 * `eta_fp16` is the fidelity-tier weight of the co-activation; `source_id` is
 * the producing detector/rule/correlation id. `now_rel` feeds last_reinf /
 * first_seen only.
 *
 * source_id sentinels: WAKE_TAC_SRC_NONE (0) is rejected as WAKE_TAC_INVALID;
 * WAKE_TAC_SRC_OTHER (0xFFFF) is remapped to 0xFFFE rather than dropped, so a
 * producer whose stable hash lands on the overflow sentinel merges with one
 * other producer (conservative: fewer distinct sources, harder to corroborate)
 * instead of having every co-activation silently discarded. */
wake_tac_result_t wake_tac_reinforce(wake_tac_t *t,
                                     const uint8_t *entity_key, size_t entity_len,
                                     uint32_t t_a, uint32_t t_b,
                                     uint16_t eta_fp16, uint16_t source_id,
                                     uint32_t now_rel);

/* Reinforce every unordered pair of `acts` on `entity_key` in one call.
 * Returns the number of pairs applied (0 if n < 2 or the key is empty).
 * Per-pair refusals (cap, budget, quarantine) are silent and not counted. */
uint32_t wake_tac_reinforce_batch(wake_tac_t *t,
                                  const uint8_t *entity_key, size_t entity_len,
                                  const wake_tac_activation_t *acts, uint32_t n,
                                  uint32_t now_rel);

/* --------------------------------------------------------------------------
 * Maintenance (caller timer)
 * -------------------------------------------------------------------------- */

/* Apply EXACTLY ONE decay factor to every live edge (the novel or corroborated
 * rate per its corroboration state), tombstone anything below noise_floor, and
 * rebuild the occupancy sidecar from the survivors. One call == one tick; the
 * caller drives cadence. Returns the number of edges evicted this pass.
 * Single-threaded; no concurrent reinforce. */
uint32_t wake_tac_decay(wake_tac_t *t);

/* --------------------------------------------------------------------------
 * Read path (external queries; never writes W)
 * -------------------------------------------------------------------------- */

/* Fill `out` with the coupling landscape for `entity_key`: total mass over
 * live non-quarantined edges, the live edge count, and the strongest edges
 * (up to WAKE_TAC_QUERY_TOP_MAX). Returns false if the entity has no edges. */
bool wake_tac_query(const wake_tac_t *t,
                    const uint8_t *entity_key, size_t entity_len,
                    wake_tac_snapshot_t *out);

/* Route this cycle's activations through the coupling weights:
 *   out[j].input_fp16 = sum over i of w(t_i, t_j) * a(t_i)
 * A pure read: it does not modify any weight. Returns the number of entries
 * written to `out`: min(n, out_cap, WAKE_TAC_QUERY_TOP_MAX). When that is
 * less than `n` only the FIRST that many activations are routed (both as
 * outputs and as coupling endpoints); the caller sees the shortfall in the
 * return value and should pass its highest-eta activations first. */
uint32_t wake_tac_route(const wake_tac_t *t,
                        const uint8_t *entity_key, size_t entity_len,
                        const wake_tac_activation_t *acts, uint32_t n,
                        wake_tac_input_t *out, uint32_t out_cap);

/* --------------------------------------------------------------------------
 * Iteration and statistics (cold path)
 * -------------------------------------------------------------------------- */

/* Consistent snapshot of one slot's atomic fields (cache line 0 + entity_hash).
 * The ident[] blob is left zeroed; see the entry layout note. Returns false
 * for an empty/tombstone/not-yet-published slot or one reclaimed mid-read. */
bool wake_tac_read_entry(const wake_tac_t *t, uint32_t slot,
                         wake_tac_entry_t *out);

typedef bool (*wake_tac_iter_fn)(const wake_tac_entry_t *entry, void *ctx);

/* Visit every live entry. Return false from the callback to stop. */
uint32_t wake_tac_iterate(const wake_tac_t *t, wake_tac_iter_fn fn, void *ctx);

void wake_tac_stats(const wake_tac_t *t, wake_tac_stats_t *out);

#ifdef __cplusplus
}
#endif

#endif /* WAKE_TAC_H */
