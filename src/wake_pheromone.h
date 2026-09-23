/*
 * wake_pheromone.h: WAKE Pheromone Table
 *
 * Stigmergy-inspired shared memory data structure for distributed threat
 * signal accumulation, decay, and reinforcement.
 *
 * Design:
 *   - Lookup is a bounded atomic probe with no lock. read_entry spins
 *     until the seqlock version is even.
 *   - 128-byte entries: hot fields in the first 64 bytes (probed every
 *     lookup), full entity in the next 64 (read only for display/export).
 *     64 bytes is one hardware cache line only where the line size is 64.
 *   - Open addressing with bounded linear probing (max 8 probes)
 *   - Seqlock protects entity writes (64 bytes, can't be atomic)
 *   - mmap-backed so more than one process can map one table. Opening a
 *     table installs its SipHash key as the process-global key.
 *   - Atomic decay with tombstone eviction
 *
 * Concurrency model:
 *   - key_hash: atomic CAS for slot claim/eviction
 *   - confidence, hit_count, src_count: atomic fetch-add (hot path)
 *   - version: seqlock for entity read/write (cold path only)
 *   - Decay runs single-threaded on the host application's timer (no contention)
 *
 * Memory layout (mmap'd file):
 *   [0..255]   wake_pheromone_header_t
 *   [256..]    wake_pheromone_entry_t[capacity]
 *
 * Copyright (c) 2026 Advens. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef WAKE_PHEROMONE_H
#define WAKE_PHEROMONE_H

#include "wake_entity.h"

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

/* Maximum linear probe distance. Lookup checks at most this many slots. */
#define WAKE_PHT_PROBE_MAX  8

/* Special key_hash sentinel values */
#define WAKE_PHT_SLOT_EMPTY     UINT64_C(0)
#define WAKE_PHT_SLOT_TOMBSTONE UINT64_C(0xDEADDEADDEADDEAD)

/* Default configuration */
#define WAKE_PHT_DEFAULT_CAPACITY      65536   /* 64K entries, 8 MiB */
#define WAKE_PHT_DEFAULT_DECAY_FP16    62259   /* 0.95 per cycle */
#define WAKE_PHT_DEFAULT_NOISE_FLOOR   100     /* eviction threshold */

/* Header magic: "WAKEPHT\0" as little-endian uint64 */
#define WAKE_PHT_MAGIC   UINT64_C(0x0054485045414B57)
#define WAKE_PHT_VERSION 1

/* Behavioral phase flags: OR'd into phase_flags on deposit */
#define WAKE_PHASE_SCAN       0x01u
#define WAKE_PHASE_BRUTE      0x02u
#define WAKE_PHASE_CREDENTIAL 0x04u
#define WAKE_PHASE_EXFIL      0x08u
#define WAKE_PHASE_C2         0x10u
#define WAKE_PHASE_LATERAL    0x20u
#define WAKE_PHASE_EDR        0x40u

/* --------------------------------------------------------------------------
 * Pheromone table entry: 128 bytes (two 64-byte groups)
 *
 * Bytes 0-63: hot fields (touched on every probe)
 * Bytes 64-127: cold field (entity data, seqlock-protected)
 *
 * Hot-path operations (deposit, lookup) only touch bytes 0-63.
 * Cold-path operations (display, export) read both via seqlock.
 * 64 bytes is one hardware cache line only where the line size is 64.
 * -------------------------------------------------------------------------- */
typedef struct {
    /* === Cache line 0: hot fields === */
    _Atomic uint64_t key_hash;       /*  8B: slot state + entity identity    */
    _Atomic uint32_t confidence;     /*  4B: accumulated evidence            */
    _Atomic uint32_t hit_count;      /*  4B: total observation count         */
    _Atomic uint32_t last_update;    /*  4B: seconds since table epoch       */
    _Atomic uint16_t src_count;      /*  2B: independent source count        */
    uint8_t          action;         /*  1B: primary action context          */
    uint8_t          outcome;        /*  1B: primary outcome context         */
    uint32_t         first_seen;     /*  4B: seconds since table epoch       */
    uint32_t         tenant_id;      /*  4B: tenant isolation key            */
    _Atomic uint32_t version;        /*  4B: seqlock for entity writes       */
    _Atomic uint32_t phase_flags;    /*  4B: behavioral phase bitmask        */
    uint8_t          _pad0[24];      /* 24B: pad to 64 bytes                 */

    /* === Cache line 1: cold field === */
    wake_entity_t    entity;         /* 64B: full entity (seqlock-protected) */
} __attribute__((aligned(128))) wake_pheromone_entry_t;

_Static_assert(sizeof(wake_pheromone_entry_t) == 128,
    "pheromone entry must be exactly 128 bytes");

/* --------------------------------------------------------------------------
 * Pheromone table header: 256 bytes (mmap'd, at file offset 0)
 * -------------------------------------------------------------------------- */
typedef struct {
    uint64_t magic;                  /*   8B */
    uint32_t format_version;         /*   4B */
    uint32_t capacity;               /*   4B: slot count (power of 2) */
    uint64_t mask;                   /*   8B: capacity - 1 */
    uint8_t  hash_key[16];           /*  16B: SipHash key for entity hashing */
    uint32_t epoch;                  /*   4B: Unix time at table creation */
    uint32_t decay_factor_fp16;      /*   4B: 0.16 fixed-point (65536=1.0) */
    uint32_t noise_floor;            /*   4B: confidence below this = dead */
    uint8_t  _reserved[204];        /* 204B: pad to 256 bytes */
} wake_pheromone_header_t;

_Static_assert(sizeof(wake_pheromone_header_t) == 256,
    "pheromone header must be exactly 256 bytes");

/* --------------------------------------------------------------------------
 * Table handle (in-process, not mmap'd)
 * -------------------------------------------------------------------------- */
typedef struct {
    wake_pheromone_header_t *header;
    wake_pheromone_entry_t  *entries;
    void                    *map_base;
    size_t                   map_size;
    int                      fd;
} wake_pheromone_t;

/* --------------------------------------------------------------------------
 * Configuration for table creation
 * -------------------------------------------------------------------------- */
typedef struct {
    uint32_t capacity;           /* Must be power of 2 (0 = default 64K) */
    uint32_t decay_factor_fp16;  /* 0 = default 0.95 */
    uint32_t noise_floor;        /* 0 = default 100 */
} wake_pheromone_config_t;

/* --------------------------------------------------------------------------
 * Table lifecycle
 * -------------------------------------------------------------------------- */

/*
 * Create a new pheromone table backed by a file at `path`.
 * Truncates any existing file. Generates a random SipHash key and sets
 * it globally via wake_hash_set_key().
 *
 * Returns NULL on error (errno set).
 */
wake_pheromone_t *wake_pheromone_create(const char *path,
                                        const wake_pheromone_config_t *cfg);

/*
 * Open an existing pheromone table from `path`.
 * Validates magic/version. Sets global SipHash key from header.
 *
 * Returns NULL on error (errno set).
 */
wake_pheromone_t *wake_pheromone_open(const char *path);

/*
 * Close and unmap the table. Pointer is invalid after this call.
 */
void wake_pheromone_close(wake_pheromone_t *pt);

/* --------------------------------------------------------------------------
 * Hot-path operations (lockfree, O(1) amortized)
 * -------------------------------------------------------------------------- */

/*
 * Deposit a local observation.
 *
 * If the entity exists: atomically adds confidence_delta and increments
 * hit_count. Does NOT increment src_count (same local source).
 *
 * If the entity doesn't exist: claims a slot via CAS, writes entity
 * under seqlock, sets initial confidence.
 *
 * Returns new confidence value, or 0 if table is full in probe range.
 */
uint32_t wake_pheromone_deposit(wake_pheromone_t *pt,
                                const wake_entity_t *entity,
                                wake_action_t action,
                                wake_outcome_t outcome,
                                uint32_t tenant_id,
                                uint32_t confidence_delta,
                                uint32_t phase_flags);

/*
 * Lookup current confidence for an entity.
 * Returns confidence, or 0 if not found.
 * Touches only cache line 0 (hot fields).
 */
uint32_t wake_pheromone_lookup(const wake_pheromone_t *pt,
                               const wake_entity_t *entity);

/*
 * Reinforce from a remote mesh signal.
 *
 * Same as deposit, but also atomically increments src_count
 * (independent source from another node).
 */
uint32_t wake_pheromone_reinforce(wake_pheromone_t *pt,
                                  const wake_entity_t *entity,
                                  wake_action_t action,
                                  wake_outcome_t outcome,
                                  uint32_t tenant_id,
                                  uint32_t confidence_delta,
                                  uint32_t phase_flags);

/*
 * Remove an entity from the table (tombstone it).
 * Returns true if found and removed, false if not found.
 */
bool wake_pheromone_remove(wake_pheromone_t *pt,
                           const wake_entity_t *entity);

/* --------------------------------------------------------------------------
 * Maintenance operations (called by the host application)
 * -------------------------------------------------------------------------- */

/*
 * Apply decay to all entries. For each live entry:
 *   new_confidence = (old_confidence * decay_factor) >> 16
 *
 * Entries that fall below noise_floor are tombstoned (evicted).
 *
 * Returns the number of entries evicted this cycle.
 */
uint32_t wake_pheromone_decay(wake_pheromone_t *pt);

/* --------------------------------------------------------------------------
 * Read operations (cold path, uses seqlock)
 * -------------------------------------------------------------------------- */

/*
 * Read a full entry snapshot (including entity data).
 * Uses seqlock to ensure consistent read of the 64-byte entity.
 *
 * Returns true if slot contains a live entry, false if empty/tombstone.
 * On true, *out is filled with a consistent snapshot.
 */
bool wake_pheromone_read_entry(const wake_pheromone_t *pt,
                               uint32_t slot_index,
                               wake_pheromone_entry_t *out);

/*
 * Iterate all live entries. Callback receives a consistent snapshot.
 * Return false from callback to stop iteration.
 *
 * Returns number of entries visited.
 */
typedef bool (*wake_pheromone_iter_fn)(const wake_pheromone_entry_t *entry,
                                       void *ctx);

uint32_t wake_pheromone_iterate(const wake_pheromone_t *pt,
                                wake_pheromone_iter_fn fn, void *ctx);

/* --------------------------------------------------------------------------
 * Statistics
 * -------------------------------------------------------------------------- */
typedef struct {
    uint32_t capacity;
    uint32_t occupied;       /* live entries */
    uint32_t tombstones;     /* tombstone slots */
    uint32_t max_probe_len;  /* longest observed probe chain */
    uint64_t total_confidence; /* sum of all live confidences */
} wake_pheromone_stats_t;

void wake_pheromone_stats(const wake_pheromone_t *pt,
                          wake_pheromone_stats_t *out);

#ifdef __cplusplus
}
#endif

#endif /* WAKE_PHEROMONE_H */
