/*
 * wake_tac.c: WAKE Transient Associative Coupling table implementation
 *
 * Concurrency:
 *   - Writes (reinforce, reinforce_batch, decay, reset) come from a single
 *     writer. Concurrent writers are not supported.
 *   - Reads (query, route, read_entry, iterate, stats) may run concurrently
 *     with the writer, from a query thread. They use atomic loads on the
 *     counters. entity_hash is atomic; the 56-byte ident copy is written
 *     under version and is not read concurrently.
 *   - Hashing uses header->hash_key via wake_hash_bytes_keyed(); the
 *     process-global SipHash key (pheromone / wake_entity_hash) is never
 *     touched.
 *
 * Copyright (c) 2026 Advens. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "wake_tac.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* Fixed key for label hashing: not secret, must be identical across processes
 * so wake_tac_pack_label() is deterministic everywhere. */
static const uint8_t k_label_key[16] = {
    0x77, 0x61, 0x6b, 0x65, 0x74, 0x61, 0x63, 0x6c,
    0x61, 0x62, 0x65, 0x6c, 0x6b, 0x65, 0x79, 0x31
};

/* =========================================================================
 * Internal helpers
 * ========================================================================= */

static inline bool
is_power_of_2(uint32_t x)
{
    return x > 0 && (x & (x - 1)) == 0;
}

static inline uint32_t
current_epoch_seconds(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint32_t)ts.tv_sec;
}

static inline size_t
compute_map_size(uint32_t capacity, uint32_t occ_slots)
{
    return sizeof(wake_tac_header_t)
         + (size_t)capacity * sizeof(wake_tac_entry_t)
         + (size_t)occ_slots * sizeof(wake_tac_occ_t);
}

/* SipHash of the entity key, avoiding the occupancy-empty sentinel (0). */
static inline uint64_t
entity_hash_of(const wake_tac_t *t, const uint8_t *key, size_t len)
{
    uint64_t h = wake_hash_bytes_keyed(key, len, t->header->hash_key);
    return h ? h : UINT64_C(1);
}

/* SipHash of (entity_hash, t_lo, t_hi), avoiding the slot sentinels. */
static inline uint64_t
slot_hash_of(const wake_tac_t *t, uint64_t ehash, uint32_t t_lo, uint32_t t_hi)
{
    uint8_t buf[16];
    memcpy(buf, &ehash, 8);
    memcpy(buf + 8, &t_lo, 4);
    memcpy(buf + 12, &t_hi, 4);
    uint64_t h = wake_hash_bytes_keyed(buf, sizeof(buf), t->header->hash_key);
    if (h == WAKE_TAC_SLOT_EMPTY || h == WAKE_TAC_SLOT_TOMBSTONE)
        h ^= UINT64_C(1);
    return h;
}

static inline void
cpu_relax(void)
{
#if defined(__aarch64__)
    __asm__ volatile("yield" ::: "memory");
#elif defined(__x86_64__)
    __asm__ volatile("pause" ::: "memory");
#endif
}

static inline bool
edge_corroborated(const wake_tac_header_t *h, uint8_t src_count, uint16_t eta_max)
{
    return src_count >= h->corroboration_src_min
        && eta_max >= WAKE_TAC_ETA_STRONG_FP16;
}

/* Atomic max on a uint16 field via CAS loop. */
static inline void
atomic_max_u16(_Atomic uint16_t *p, uint16_t v)
{
    uint16_t cur = atomic_load_explicit(p, memory_order_relaxed);
    while (cur < v &&
           !atomic_compare_exchange_weak_explicit(p, &cur, v,
               memory_order_relaxed, memory_order_relaxed))
        ;
}

/* =========================================================================
 * Occupancy sidecar: per-entity edge index
 *
 * Both the cap check and the weakest-edge search are O(per_entity_cap) through
 * this index. Nothing on the write path may scan the whole table: an entity
 * flooded with distinct pairs would then cost a capacity-sized scan per pair,
 * which IS the eviction-DoS the cap exists to stop.
 *
 * Single-writer. Readers only touch live_count, via
 * wake_tac_stats. Drift (probe exhaustion, a crash mid-update) self-heals on
 * the next decay pass, which rebuilds the sidecar from the live entries.
 * ========================================================================= */

/* Find the sidecar slot for `ehash`. If `claim`, take a free slot when the
 * entity is unknown. Returns NULL when absent (or the probe window is full). */
static wake_tac_occ_t *
occ_find(const wake_tac_t *t, uint64_t ehash, bool claim)
{
    uint32_t slots = t->header->occ_slots;
    uint64_t base = ehash & (uint64_t)(slots - 1);
    for (uint32_t p = 0; p < WAKE_TAC_OCC_PROBE_MAX; p++) {
        wake_tac_occ_t *o = &t->occ[(base + p) & (slots - 1)];
        uint64_t e = atomic_load_explicit(&o->entity_hash, memory_order_acquire);
        if (e == ehash)
            return o;
        if (e == 0) {
            if (!claim)
                return NULL;
            atomic_store_explicit(&o->live_count, 0, memory_order_relaxed);
            atomic_store_explicit(&o->entity_hash, ehash, memory_order_release);
            return o;
        }
    }
    return NULL;
}

/* Live edge count for `ehash`, 0 if unknown. */
static uint32_t
occ_count(const wake_tac_t *t, uint64_t ehash)
{
    const wake_tac_occ_t *o = occ_find(t, ehash, false);
    return o ? atomic_load_explicit(&o->live_count, memory_order_relaxed) : 0;
}

/* Record entry `idx` as a live edge of `ehash`. Returns false when the entity
 * could not be tracked (sidecar probe window full, or the per-entity index is
 * somehow already full); the caller must then fail closed, never insert an
 * untracked (and therefore uncapped) edge. */
static bool
occ_add_slot(wake_tac_t *t, uint64_t ehash, uint32_t idx)
{
    wake_tac_occ_t *o = occ_find(t, ehash, true);
    if (!o)
        return false;
    uint32_t c = atomic_load_explicit(&o->live_count, memory_order_relaxed);
    if (c >= WAKE_TAC_PER_ENTITY_CAP_MAX)
        return false;
    atomic_store_explicit(&o->slot[c], idx, memory_order_relaxed);
    atomic_store_explicit(&o->live_count, c + 1, memory_order_release);
    return true;
}

/* Drop entry `idx` from `ehash`'s index (swap-with-last). */
static void
occ_del_slot(wake_tac_t *t, uint64_t ehash, uint32_t idx)
{
    wake_tac_occ_t *o = occ_find(t, ehash, false);
    if (!o)
        return;
    uint32_t c = atomic_load_explicit(&o->live_count, memory_order_relaxed);
    for (uint32_t i = 0; i < c && i < WAKE_TAC_PER_ENTITY_CAP_MAX; i++) {
        if (atomic_load_explicit(&o->slot[i], memory_order_relaxed) != idx)
            continue;
        uint32_t last = atomic_load_explicit(&o->slot[c - 1],
                                             memory_order_relaxed);
        atomic_store_explicit(&o->slot[i], last, memory_order_relaxed);
        atomic_store_explicit(&o->live_count, c - 1, memory_order_release);
        return;
    }
}

/* =========================================================================
 * Slot lookup
 * ========================================================================= */

/* Find the slot holding `slot_key`, or UINT32_MAX. */
static uint32_t
find_slot(const wake_tac_t *t, uint64_t slot_key)
{
    uint64_t base = slot_key & t->header->mask;
    for (uint32_t p = 0; p < WAKE_TAC_PROBE_MAX; p++) {
        uint32_t idx = (uint32_t)((base + p) & t->header->mask);
        uint64_t kh = atomic_load_explicit(&t->entries[idx].key_hash,
                                           memory_order_acquire);
        if (kh == slot_key)
            return idx;
        if (kh == WAKE_TAC_SLOT_EMPTY)
            return UINT32_MAX;
    }
    return UINT32_MAX;
}

/* =========================================================================
 * Lifecycle
 * ========================================================================= */

wake_tac_t *
wake_tac_create(const char *path, const wake_tac_config_t *cfg)
{
    uint32_t capacity = cfg && cfg->capacity ? cfg->capacity
                                             : WAKE_TAC_DEFAULT_CAPACITY;
    /* occ_slots defaults to `capacity` (not the constant): the sidecar must be
     * able to hold every entity that could carry a live edge. */
    uint32_t occ_slots = cfg && cfg->occ_slots ? cfg->occ_slots : capacity;
    uint32_t budget = cfg && cfg->budget_per_source ? cfg->budget_per_source
                                                    : WAKE_TAC_DEFAULT_BUDGET_PER_SOURCE;

    uint32_t d_novel = cfg && cfg->decay_novel_fp16 ? cfg->decay_novel_fp16
                                                    : WAKE_TAC_DEFAULT_DECAY_NOVEL_FP16;
    uint32_t d_corr = cfg && cfg->decay_corr_fp16 ? cfg->decay_corr_fp16
                                                  : WAKE_TAC_DEFAULT_DECAY_CORR_FP16;
    uint16_t cap = cfg && cfg->per_entity_cap ? cfg->per_entity_cap
                                              : (uint16_t)WAKE_TAC_DEFAULT_PER_ENTITY_CAP;

    /* A decay factor >= 1.0 would GROW every weight each tick: nothing would
     * ever reach noise_floor and the table would fill permanently. Refuse it
     * rather than let a config bug turn the memory into a leak. occ_slots <
     * capacity would let the sidecar fail to track an entity (which then goes
     * uncapped, or fails closed): refuse it. */
    if (!is_power_of_2(capacity) || !is_power_of_2(occ_slots) ||
        capacity > WAKE_TAC_MAX_CAPACITY || occ_slots < capacity ||
        occ_slots > WAKE_TAC_MAX_CAPACITY ||
        budget > UINT16_MAX || budget < WAKE_TAC_DELTA_MAX ||
        d_novel >= 65536u || d_corr >= 65536u ||
        cap == 0 || cap > WAKE_TAC_PER_ENTITY_CAP_MAX) {
        errno = EINVAL;
        return NULL;
    }

    size_t map_size = compute_map_size(capacity, occ_slots);

    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (fd < 0)
        return NULL;
    if (ftruncate(fd, (off_t)map_size) < 0) {
        close(fd);
        return NULL;
    }

    void *base = mmap(NULL, map_size, PROT_READ | PROT_WRITE,
                      MAP_SHARED, fd, 0);
    if (base == MAP_FAILED) {
        close(fd);
        return NULL;
    }
    memset(base, 0, map_size);

    wake_tac_header_t *hdr = (wake_tac_header_t *)base;
    hdr->magic          = WAKE_TAC_MAGIC;
    hdr->format_version = WAKE_TAC_VERSION;
    hdr->capacity       = capacity;
    hdr->mask           = (uint64_t)(capacity - 1);
    hdr->epoch          = current_epoch_seconds();
    hdr->decay_novel_fp16 = d_novel;
    hdr->decay_corr_fp16 = d_corr;
    hdr->noise_floor    = cfg && cfg->noise_floor ? cfg->noise_floor
                                                  : WAKE_TAC_DEFAULT_NOISE_FLOOR;
    hdr->occ_slots      = occ_slots;
    hdr->budget_per_source = budget;
    hdr->per_entity_cap = cap;
    hdr->corroboration_src_min = cfg && cfg->corroboration_src_min
                                     ? cfg->corroboration_src_min
                                     : WAKE_TAC_DEFAULT_CORROBORATION_MIN;
    hdr->tick_seconds   = cfg && cfg->tick_seconds ? cfg->tick_seconds
                                                   : WAKE_TAC_DEFAULT_TICK_SECONDS;
    hdr->quarantine_min_w = cfg && cfg->quarantine_min_w
                                ? cfg->quarantine_min_w
                                : WAKE_TAC_DEFAULT_QUARANTINE_MIN_W;

    int urand = open("/dev/urandom", O_RDONLY);
    if (urand < 0) {
        munmap(base, map_size);
        close(fd);
        return NULL;
    }
    ssize_t n = read(urand, hdr->hash_key, sizeof(hdr->hash_key));
    close(urand);
    if (n != (ssize_t)sizeof(hdr->hash_key)) {
        munmap(base, map_size);
        close(fd);
        errno = EIO;
        return NULL;
    }

    msync(base, sizeof(*hdr), MS_SYNC);

    wake_tac_t *t = malloc(sizeof(*t));
    if (!t) {
        munmap(base, map_size);
        close(fd);
        return NULL;
    }
    t->header   = hdr;
    t->entries  = (wake_tac_entry_t *)((char *)base + sizeof(*hdr));
    t->occ      = (wake_tac_occ_t *)((char *)t->entries +
                    (size_t)capacity * sizeof(wake_tac_entry_t));
    t->map_base = base;
    t->map_size = map_size;
    t->fd       = fd;
    return t;
}

wake_tac_t *
wake_tac_open(const char *path)
{
    int fd = open(path, O_RDWR);
    if (fd < 0)
        return NULL;

    wake_tac_header_t tmp;
    ssize_t n = read(fd, &tmp, sizeof(tmp));
    if (n != (ssize_t)sizeof(tmp)) {
        close(fd);
        errno = EIO;
        return NULL;
    }
    /* Validate every field the hot paths trust: a stale or corrupted 0600 file
     * must not be able to make decay grow weights, refuse every reinforce, or
     * index past the sidecar's slot array. */
    if (tmp.magic != WAKE_TAC_MAGIC || tmp.format_version != WAKE_TAC_VERSION ||
        !is_power_of_2(tmp.capacity) || !is_power_of_2(tmp.occ_slots) ||
        tmp.capacity > WAKE_TAC_MAX_CAPACITY ||
        tmp.occ_slots < tmp.capacity || tmp.occ_slots > WAKE_TAC_MAX_CAPACITY ||
        tmp.mask != (uint64_t)(tmp.capacity - 1) ||
        tmp.decay_novel_fp16 == 0 || tmp.decay_novel_fp16 >= 65536u ||
        tmp.decay_corr_fp16 == 0 || tmp.decay_corr_fp16 >= 65536u ||
        tmp.noise_floor == 0 ||
        tmp.noise_floor >= tmp.budget_per_source * WAKE_TAC_BUDGET_SLOTS ||
        tmp.budget_per_source < WAKE_TAC_DELTA_MAX ||
        tmp.budget_per_source > UINT16_MAX ||
        tmp.per_entity_cap == 0 ||
        tmp.per_entity_cap > WAKE_TAC_PER_ENTITY_CAP_MAX ||
        tmp.corroboration_src_min == 0) {
        close(fd);
        errno = EINVAL;
        return NULL;
    }

    size_t map_size = compute_map_size(tmp.capacity, tmp.occ_slots);
    struct stat st;
    if (fstat(fd, &st) < 0 || (size_t)st.st_size < map_size) {
        close(fd);
        errno = EINVAL;
        return NULL;
    }

    void *base = mmap(NULL, map_size, PROT_READ | PROT_WRITE,
                      MAP_SHARED, fd, 0);
    if (base == MAP_FAILED) {
        close(fd);
        return NULL;
    }

    wake_tac_header_t *hdr = (wake_tac_header_t *)base;
    wake_tac_t *t = malloc(sizeof(*t));
    if (!t) {
        munmap(base, map_size);
        close(fd);
        return NULL;
    }
    t->header   = hdr;
    t->entries  = (wake_tac_entry_t *)((char *)base + sizeof(*hdr));
    t->occ      = (wake_tac_occ_t *)((char *)t->entries +
                    (size_t)hdr->capacity * sizeof(wake_tac_entry_t));
    t->map_base = base;
    t->map_size = map_size;
    t->fd       = fd;
    return t;
}

void
wake_tac_close(wake_tac_t *t)
{
    if (!t)
        return;
    if (t->map_base && t->map_base != MAP_FAILED)
        munmap(t->map_base, t->map_size);
    if (t->fd >= 0)
        close(t->fd);
    free(t);
}

void
wake_tac_reset(wake_tac_t *t)
{
    if (!t)
        return;
    memset(t->entries, 0,
           (size_t)t->header->capacity * sizeof(wake_tac_entry_t));
    memset(t->occ, 0,
           (size_t)t->header->occ_slots * sizeof(wake_tac_occ_t));
}

/* =========================================================================
 * Time and packing
 * ========================================================================= */

uint32_t
wake_tac_now(const wake_tac_t *t)
{
    return current_epoch_seconds() - t->header->epoch;
}

uint32_t
wake_tac_pack(uint16_t base, uint8_t sub)
{
    return (uint32_t)base | ((uint32_t)sub << 16);
}

uint32_t
wake_tac_pack_label(const char *label, size_t len)
{
    uint64_t h = wake_hash_bytes_keyed(label, len, k_label_key);
    return ((uint32_t)h & 0x00FFFFFFu) | ((uint32_t)WAKE_TAC_TECH_HASHED << 24);
}

/* =========================================================================
 * Write path
 * ========================================================================= */

/* Map a caller source_id onto a usable one. WAKE_TAC_SRC_NONE (0) is invalid
 * and must be rejected by the caller first. WAKE_TAC_SRC_OTHER (0xFFFF) is the
 * overflow-bucket sentinel; a producer whose stable hash lands there is
 * folded onto 0xFFFE (merges with one real producer, conservative: fewer
 * distinct sources, harder to corroborate) rather than corrupting the bucket. */
static inline uint16_t
normalize_source(uint16_t s)
{
    return s == WAKE_TAC_SRC_OTHER ? (uint16_t)(WAKE_TAC_SRC_OTHER - 1u) : s;
}

/* True when `source_id` already holds a budget slot on this edge (a named slot,
 * or the overflow bucket once it is in use; past the named slots the table
 * cannot tell a repeat from a newcomer, so it assumes repeat). */
static bool
budget_knows_source(const wake_tac_entry_t *e, uint16_t source_id)
{
    for (int i = 0; i < WAKE_TAC_BUDGET_NAMED; i++) {
        if (e->budget[i].source_id == source_id)
            return true;
        if (e->budget[i].source_id == WAKE_TAC_SRC_NONE)
            return false;   /* free named slot => this source is new */
    }
    return e->budget[WAKE_TAC_BUDGET_NAMED].source_id != WAKE_TAC_SRC_NONE;
}

/* Charge `delta` force units to `source_id`'s budget slot in `e`. Claims a
 * free named slot or the shared OTHER bucket. Returns false if the slot is
 * over budget. `new_source` is set to true when a new distinct source is
 * counted (src_count saturates at WAKE_TAC_BUDGET_SLOTS; see wake_tac.h). */
static bool
budget_charge(wake_tac_entry_t *e, const wake_tac_header_t *h,
              uint16_t source_id, uint32_t delta, bool *new_source)
{
    *new_source = false;
    int free_named = -1;
    for (int i = 0; i < WAKE_TAC_BUDGET_NAMED; i++) {
        if (e->budget[i].source_id == source_id) {
            if ((uint32_t)e->budget[i].spent + delta > h->budget_per_source)
                return false;
            e->budget[i].spent = (uint16_t)(e->budget[i].spent + delta);
            return true;
        }
        if (free_named < 0 && e->budget[i].source_id == WAKE_TAC_SRC_NONE)
            free_named = i;
    }
    if (free_named >= 0) {
        if (delta > h->budget_per_source)
            return false;
        e->budget[free_named].source_id = source_id;
        e->budget[free_named].spent = (uint16_t)delta;
        *new_source = true;
        return true;
    }
    /* All named slots taken by other sources: shared OTHER bucket. */
    wake_tac_budget_t *o = &e->budget[WAKE_TAC_BUDGET_NAMED];
    if ((uint32_t)o->spent + delta > h->budget_per_source)
        return false;
    if (o->source_id == WAKE_TAC_SRC_NONE) {
        o->source_id = WAKE_TAC_SRC_OTHER;
        *new_source = true;   /* the 5th distinct source; further ones cannot
                               * be told apart from it, so they never count */
    }
    o->spent = (uint16_t)(o->spent + delta);
    return true;
}

/* Outlier-reinforcement quarantine. Trip when a SINGLE source holds
 * >= WAKE_TAC_QUARANTINE_SHARE_PCT of an edge's weight past the floor: one
 * producer manufacturing a coupling on its own. Independent corroboration
 * (src_count >= 2) clears it, so this can never bury a real multi-witness
 * campaign. Single-writer; called after the weight update. */
static void
quarantine_reassess(wake_tac_entry_t *e, const wake_tac_header_t *h)
{
    if (h->quarantine_min_w == 0 || h->quarantine_min_w == UINT32_MAX)
        return;

    uint8_t sc = atomic_load_explicit(&e->src_count, memory_order_relaxed);
    if (sc >= 2) {
        atomic_store_explicit(&e->quarantine, 0, memory_order_relaxed);
        return;
    }

    uint32_t w = atomic_load_explicit(&e->weight, memory_order_relaxed);
    if (w < h->quarantine_min_w)
        return;

    uint32_t top = 0;
    for (int i = 0; i < WAKE_TAC_BUDGET_SLOTS; i++)
        if (e->budget[i].spent > top)
            top = e->budget[i].spent;

    if ((uint64_t)top * 100u >= (uint64_t)w * WAKE_TAC_QUARANTINE_SHARE_PCT)
        atomic_store_explicit(&e->quarantine, 1, memory_order_relaxed);
}

/* Reinforce the canonical edge (t_lo,t_hi) on the entity identified by
 * (ehash, key, len) with one or two witnesses. w1_src == WAKE_TAC_SRC_NONE
 * means a single witness. */
static wake_tac_result_t
apply_edge(wake_tac_t *t,
           uint64_t ehash, const uint8_t *key, size_t len,
           uint32_t t_lo, uint32_t t_hi,
           uint16_t w0_eta, uint16_t w0_src,
           uint16_t w1_eta, uint16_t w1_src,
           uint32_t now_rel)
{
    const wake_tac_header_t *h = t->header;
    uint16_t eta_hi = w1_src != WAKE_TAC_SRC_NONE && w1_eta > w0_eta
                          ? w1_eta : w0_eta;
    uint16_t eta_lo = w1_src != WAKE_TAC_SRC_NONE && w1_eta < w0_eta
                          ? w1_eta : w0_eta;
    uint32_t delta = WAKE_TAC_DELTA(eta_lo);   /* joint strength = weaker leg */
    if (delta == 0)
        delta = 1;

    uint64_t slot_key = slot_hash_of(t, ehash, t_lo, t_hi);
    uint64_t base = slot_key & h->mask;

    uint32_t existing = find_slot(t, slot_key);
    if (existing != UINT32_MAX) {
        wake_tac_entry_t *e = &t->entries[existing];

        /* A quarantined edge refuses the sources it already carries; those
         * are the ones that manufactured the imbalance. A genuinely NEW
         * distinct source is allowed through: independent corroboration is
         * exactly the evidence that clears the quarantine. */
        if (atomic_load_explicit(&e->quarantine, memory_order_relaxed) &&
            budget_knows_source(e, w0_src) &&
            (w1_src == WAKE_TAC_SRC_NONE || budget_knows_source(e, w1_src)))
            return WAKE_TAC_REFUSED_QUARANTINE;

        bool ns0 = false, ns1 = false;
        bool have2 = w1_src != WAKE_TAC_SRC_NONE && w1_src != w0_src;
        if (!budget_charge(e, h, w0_src, delta, &ns0)) {
            /* w0 is over budget. If there is a distinct second witness, let it
             * carry the reinforcement so a genuine new corroborator is not
             * lost with the exhausted source. */
            if (!have2 || !budget_charge(e, h, w1_src, delta, &ns1))
                return WAKE_TAC_REFUSED_BUDGET;
        } else if (have2) {
            budget_charge(e, h, w1_src, delta, &ns1);
        }

        atomic_fetch_add_explicit(&e->weight, delta, memory_order_relaxed);
        atomic_fetch_add_explicit(&e->reinf_count, 1, memory_order_relaxed);
        atomic_store_explicit(&e->last_reinf, now_rel, memory_order_relaxed);
        atomic_max_u16(&e->eta_max_fp16, eta_hi);
        uint8_t bump = (uint8_t)((ns0 ? 1 : 0) + (ns1 ? 1 : 0));
        if (bump) {
            uint8_t sc = atomic_load_explicit(&e->src_count,
                                              memory_order_relaxed);
            uint32_t nsc = (uint32_t)sc + bump;
            if (nsc > WAKE_TAC_BUDGET_SLOTS)
                nsc = WAKE_TAC_BUDGET_SLOTS;
            atomic_store_explicit(&e->src_count, (uint8_t)nsc,
                                  memory_order_relaxed);
        }
        quarantine_reassess(e, h);
        return WAKE_TAC_APPLIED;
    }

    /*
     * New edge. Order matters: decide, then claim a free slot, and only
     * tombstone the cap victim once the replacement slot is secured. Evicting
     * first would destroy a real coupling and then still be able to fail with
     * TABLE_FULL, leaving the entity a live edge short for nothing.
     */
    uint32_t victim = UINT32_MAX;
    if (occ_count(t, ehash) >= h->per_entity_cap) {
        /* Weakest live edge of THIS entity, via the O(cap) sidecar index. */
        const wake_tac_occ_t *o = occ_find(t, ehash, false);
        uint32_t weakest_w = UINT32_MAX;
        uint32_t n = o ? atomic_load_explicit(&o->live_count,
                                              memory_order_relaxed) : 0;
        if (n > WAKE_TAC_PER_ENTITY_CAP_MAX)
            n = WAKE_TAC_PER_ENTITY_CAP_MAX;
        for (uint32_t i = 0; i < n; i++) {
            uint32_t idx = atomic_load_explicit(&o->slot[i],
                                                memory_order_relaxed);
            if (idx >= h->capacity)
                continue;
            const wake_tac_entry_t *c = &t->entries[idx];
            uint64_t kh = atomic_load_explicit(&c->key_hash,
                                               memory_order_relaxed);
            if (kh == WAKE_TAC_SLOT_EMPTY || kh == WAKE_TAC_SLOT_TOMBSTONE)
                continue;
            /* The sidecar index can carry a stale slot pointer (a half-applied
             * occ_del_slot swap, a slot reclaimed by another entity). Never
             * evict an edge that is not actually this entity's. */
            if (atomic_load_explicit(&c->entity_hash,
                                     memory_order_relaxed) != ehash)
                continue;
            uint32_t w = atomic_load_explicit(&c->weight, memory_order_relaxed);
            if (w < weakest_w) {
                weakest_w = w;
                victim = idx;
            }
        }
        /* Replace only if the newcomer is strictly stronger than the weakest
         * edge already earned. */
        if (victim == UINT32_MAX || delta <= weakest_w)
            return WAKE_TAC_REFUSED_CAP;
    }

    /* Claim a slot BEFORE evicting anything. */
    uint32_t claimed = UINT32_MAX;
    for (uint32_t p = 0; p < WAKE_TAC_PROBE_MAX; p++) {
        uint32_t idx = (uint32_t)((base + p) & h->mask);
        wake_tac_entry_t *e = &t->entries[idx];
        uint64_t cur = atomic_load_explicit(&e->key_hash, memory_order_relaxed);
        if (cur != WAKE_TAC_SLOT_EMPTY && cur != WAKE_TAC_SLOT_TOMBSTONE)
            continue;
        uint64_t expect = cur;
        if (atomic_compare_exchange_strong_explicit(
                &e->key_hash, &expect, slot_key,
                memory_order_acq_rel, memory_order_relaxed)) {
            claimed = idx;
            break;
        }
    }
    if (claimed == UINT32_MAX)
        return WAKE_TAC_TABLE_FULL;   /* victim untouched */

    /* Replacement secured: now retire the victim. */
    if (victim != UINT32_MAX) {
        atomic_store_explicit(&t->entries[victim].weight, 0,
                              memory_order_relaxed);
        atomic_store_explicit(&t->entries[victim].key_hash,
                              WAKE_TAC_SLOT_TOMBSTONE, memory_order_release);
        occ_del_slot(t, ehash, victim);
    }

    {
        wake_tac_entry_t *e = &t->entries[claimed];
        /* A reclaimed tombstone still carries the previous edge's weight /
         * entity_hash / techniques. Hide it from concurrent readers (they skip
         * weight == 0) until it is fully built, then publish weight last. */
        atomic_store_explicit(&e->weight, 0, memory_order_relaxed);
        atomic_store_explicit(&e->t_lo, t_lo, memory_order_relaxed);
        atomic_store_explicit(&e->t_hi, t_hi, memory_order_relaxed);
        atomic_store_explicit(&e->reinf_count, 1, memory_order_relaxed);
        atomic_store_explicit(&e->last_reinf, now_rel, memory_order_relaxed);
        atomic_store_explicit(&e->eta_max_fp16, eta_hi, memory_order_relaxed);
        atomic_store_explicit(&e->quarantine, 0, memory_order_relaxed);
        atomic_store_explicit(&e->first_seen, now_rel, memory_order_relaxed);
        memset(e->budget, 0, sizeof(e->budget));
        bool ns0 = false, ns1 = false;
        budget_charge(e, h, w0_src, delta, &ns0);
        if (w1_src != WAKE_TAC_SRC_NONE && w1_src != w0_src)
            budget_charge(e, h, w1_src, delta, &ns1);
        atomic_store_explicit(&e->src_count,
                              (uint8_t)((ns0 ? 1 : 0) + (ns1 ? 1 : 0)),
                              memory_order_relaxed);

        uint32_t v = atomic_load_explicit(&e->version, memory_order_relaxed);
        uint32_t wv = (v + 1) | 1u;
        atomic_store_explicit(&e->version, wv, memory_order_release);
        atomic_store_explicit(&e->entity_hash, ehash, memory_order_release);
        uint8_t ilen = len > WAKE_TAC_IDENT_MAX ? WAKE_TAC_IDENT_MAX
                                                : (uint8_t)len;
        e->ident_len = ilen;
        e->ident_flags = len > WAKE_TAC_IDENT_MAX ? WAKE_TAC_IDENT_HASHED : 0;
        memcpy(e->ident, key, ilen);
        if (ilen < WAKE_TAC_IDENT_MAX)
            memset(e->ident + ilen, 0, WAKE_TAC_IDENT_MAX - ilen);
        atomic_store_explicit(&e->version, wv + 1, memory_order_release);

        /* Track the entity BEFORE publishing the weight. If the sidecar cannot
         * take it, fail closed; an untracked edge is an uncapped edge. This is
         * only reachable on the non-eviction path (`victim == UINT32_MAX`): the
         * eviction path's entity is already in the sidecar and occ_del_slot
         * left it a slot short, so occ_add_slot cannot fail there. Nothing was
         * evicted, the weight is still 0, so undoing the claim loses nothing. */
        if (!occ_add_slot(t, ehash, claimed)) {
            atomic_store_explicit(&e->key_hash, WAKE_TAC_SLOT_TOMBSTONE,
                                  memory_order_release);
            return WAKE_TAC_REFUSED_CAP;
        }
        atomic_store_explicit(&e->weight, delta, memory_order_release);
    }
    return WAKE_TAC_APPLIED;
}

wake_tac_result_t
wake_tac_reinforce(wake_tac_t *t,
                   const uint8_t *entity_key, size_t entity_len,
                   uint32_t t_a, uint32_t t_b,
                   uint16_t eta_fp16, uint16_t source_id,
                   uint32_t now_rel)
{
    if (!entity_key || entity_len == 0 || source_id == WAKE_TAC_SRC_NONE ||
        t_a == t_b)
        return WAKE_TAC_INVALID;
    source_id = normalize_source(source_id);

    uint32_t t_lo = t_a < t_b ? t_a : t_b;
    uint32_t t_hi = t_a < t_b ? t_b : t_a;
    uint64_t ehash = entity_hash_of(t, entity_key, entity_len);

    return apply_edge(t, ehash, entity_key, entity_len, t_lo, t_hi,
                      eta_fp16, source_id, 0, WAKE_TAC_SRC_NONE, now_rel);
}

uint32_t
wake_tac_reinforce_batch(wake_tac_t *t,
                         const uint8_t *entity_key, size_t entity_len,
                         const wake_tac_activation_t *acts, uint32_t n,
                         uint32_t now_rel)
{
    if (!entity_key || entity_len == 0 || !acts || n < 2)
        return 0;

    uint64_t ehash = entity_hash_of(t, entity_key, entity_len);
    uint32_t applied = 0;

    for (uint32_t i = 0; i < n; i++) {
        if (acts[i].source_id == WAKE_TAC_SRC_NONE)
            continue;
        uint16_t si = normalize_source(acts[i].source_id);
        for (uint32_t j = i + 1; j < n; j++) {
            if (acts[j].source_id == WAKE_TAC_SRC_NONE)
                continue;
            uint16_t sj = normalize_source(acts[j].source_id);
            uint32_t a = acts[i].technique;
            uint32_t b = acts[j].technique;
            if (a == b)
                continue;
            uint32_t t_lo = a < b ? a : b;
            uint32_t t_hi = a < b ? b : a;
            wake_tac_result_t r = apply_edge(
                t, ehash, entity_key, entity_len, t_lo, t_hi,
                acts[i].eta_fp16, si,
                acts[j].eta_fp16, sj, now_rel);
            if (r == WAKE_TAC_APPLIED)
                applied++;
        }
    }
    return applied;
}

/* =========================================================================
 * Maintenance
 * ========================================================================= */

uint32_t
wake_tac_decay(wake_tac_t *t)
{
    const wake_tac_header_t *h = t->header;
    uint32_t evicted = 0;

    /* Zero the sidecar (atomic per slot so a concurrent wake_tac_stats reader
     * never sees a torn value), then rebuild it from the survivors below.
     * A reader mid-pass sees eventually-consistent counts, never garbage. */
    for (uint32_t i = 0; i < h->occ_slots; i++) {
        atomic_store_explicit(&t->occ[i].live_count, 0, memory_order_relaxed);
        atomic_store_explicit(&t->occ[i].entity_hash, 0, memory_order_relaxed);
    }

    for (uint32_t i = 0; i < h->capacity; i++) {
        wake_tac_entry_t *e = &t->entries[i];
        uint64_t kh = atomic_load_explicit(&e->key_hash, memory_order_relaxed);
        if (kh == WAKE_TAC_SLOT_EMPTY || kh == WAKE_TAC_SLOT_TOMBSTONE)
            continue;

        uint32_t w = atomic_load_explicit(&e->weight, memory_order_relaxed);
        uint8_t sc = atomic_load_explicit(&e->src_count, memory_order_relaxed);
        uint16_t em = atomic_load_explicit(&e->eta_max_fp16,
                                           memory_order_relaxed);
        uint32_t factor = edge_corroborated(h, sc, em) ? h->decay_corr_fp16
                                                       : h->decay_novel_fp16;
        uint32_t nw = (uint32_t)(((uint64_t)w * factor) >> 16);

        if (nw < h->noise_floor) {
            atomic_store_explicit(&e->key_hash, WAKE_TAC_SLOT_TOMBSTONE,
                                  memory_order_release);
            evicted++;
            continue;
        }
        atomic_store_explicit(&e->weight, nw, memory_order_relaxed);
        occ_add_slot(t,
                     atomic_load_explicit(&e->entity_hash,
                                          memory_order_relaxed), i);
    }
    return evicted;
}

/* =========================================================================
 * Read path
 * ========================================================================= */

static void
top_insert(wake_tac_edge_t *top, uint32_t *count, const wake_tac_edge_t *cand)
{
    if (*count < WAKE_TAC_QUERY_TOP_MAX) {
        top[(*count)++] = *cand;
        return;
    }
    uint32_t min_i = 0;
    for (uint32_t i = 1; i < WAKE_TAC_QUERY_TOP_MAX; i++)
        if (top[i].weight < top[min_i].weight)
            min_i = i;
    if (cand->weight > top[min_i].weight)
        top[min_i] = *cand;
}

bool
wake_tac_query(const wake_tac_t *t,
               const uint8_t *entity_key, size_t entity_len,
               wake_tac_snapshot_t *out)
{
    if (!entity_key || entity_len == 0 || !out)
        return false;

    uint64_t ehash = entity_hash_of(t, entity_key, entity_len);
    memset(out, 0, sizeof(*out));

    for (uint32_t i = 0; i < t->header->capacity; i++) {
        const wake_tac_entry_t *e = &t->entries[i];
        uint64_t kh = atomic_load_explicit(&e->key_hash, memory_order_acquire);
        if (kh == WAKE_TAC_SLOT_EMPTY || kh == WAKE_TAC_SLOT_TOMBSTONE)
            continue;
        uint32_t w = atomic_load_explicit(&e->weight, memory_order_acquire);
        if (w == 0)
            continue;
        if (atomic_load_explicit(&e->entity_hash,
                                 memory_order_relaxed) != ehash)
            continue;
        if (atomic_load_explicit(&e->quarantine, memory_order_relaxed))
            continue;

        out->coupling_mass += w;
        out->edge_count++;
        wake_tac_edge_t ed = {
            .t_lo = atomic_load_explicit(&e->t_lo, memory_order_relaxed),
            .t_hi = atomic_load_explicit(&e->t_hi, memory_order_relaxed),
            .weight = w,
            .eta_max_fp16 = atomic_load_explicit(&e->eta_max_fp16,
                                                 memory_order_relaxed),
            .src_count = atomic_load_explicit(&e->src_count,
                                              memory_order_relaxed),
            .quarantine = 0,
        };
        top_insert(out->top, &out->top_count, &ed);
    }
    return out->edge_count > 0;
}

uint32_t
wake_tac_route(const wake_tac_t *t,
               const uint8_t *entity_key, size_t entity_len,
               const wake_tac_activation_t *acts, uint32_t n,
               wake_tac_input_t *out, uint32_t out_cap)
{
    if (!entity_key || entity_len == 0 || !acts || !out || out_cap == 0)
        return 0;

    uint32_t m = n < out_cap ? n : out_cap;
    uint64_t acc[WAKE_TAC_QUERY_TOP_MAX];
    if (m > WAKE_TAC_QUERY_TOP_MAX)
        m = WAKE_TAC_QUERY_TOP_MAX;
    for (uint32_t k = 0; k < m; k++) {
        out[k].technique = acts[k].technique;
        acc[k] = 0;
    }

    uint64_t ehash = entity_hash_of(t, entity_key, entity_len);

    for (uint32_t i = 0; i < t->header->capacity; i++) {
        const wake_tac_entry_t *e = &t->entries[i];
        uint64_t kh = atomic_load_explicit(&e->key_hash, memory_order_acquire);
        if (kh == WAKE_TAC_SLOT_EMPTY || kh == WAKE_TAC_SLOT_TOMBSTONE)
            continue;
        uint32_t w = atomic_load_explicit(&e->weight, memory_order_acquire);
        if (w == 0 ||
            atomic_load_explicit(&e->quarantine, memory_order_relaxed))
            continue;
        if (atomic_load_explicit(&e->entity_hash,
                                 memory_order_relaxed) != ehash)
            continue;
        uint32_t el = atomic_load_explicit(&e->t_lo, memory_order_relaxed);
        uint32_t eh = atomic_load_explicit(&e->t_hi, memory_order_relaxed);

        int xi = -1, xj = -1;
        for (uint32_t k = 0; k < m; k++) {
            if (acts[k].technique == el)
                xi = (int)k;
            else if (acts[k].technique == eh)
                xj = (int)k;
        }
        if (xi < 0 || xj < 0)
            continue;
        acc[xi] += ((uint64_t)w * acts[xj].eta_fp16) >> 16;
        acc[xj] += ((uint64_t)w * acts[xi].eta_fp16) >> 16;
    }

    for (uint32_t k = 0; k < m; k++)
        out[k].input_fp16 = acc[k] > UINT32_MAX ? UINT32_MAX
                                                : (uint32_t)acc[k];
    return m;
}

bool
wake_tac_read_entry(const wake_tac_t *t, uint32_t slot,
                    wake_tac_entry_t *out)
{
    if (slot >= t->header->capacity || !out)
        return false;
    const wake_tac_entry_t *e = &t->entries[slot];

    /* CL0 atomics: field-by-field atomic loads (no struct memcpy over
     * _Atomic members). `out` is caller-private, so plain assignment to its
     * atomic members is fine. */
    uint64_t kh = atomic_load_explicit(&e->key_hash, memory_order_acquire);
    if (kh == WAKE_TAC_SLOT_EMPTY || kh == WAKE_TAC_SLOT_TOMBSTONE)
        return false;
    uint32_t w = atomic_load_explicit(&e->weight, memory_order_acquire);
    if (w == 0)
        return false;   /* slot claimed but not yet published */

    memset(out, 0, sizeof(*out));
    out->key_hash     = kh;
    out->weight       = w;
    out->reinf_count  = atomic_load_explicit(&e->reinf_count, memory_order_relaxed);
    out->last_reinf   = atomic_load_explicit(&e->last_reinf, memory_order_relaxed);
    out->t_lo         = atomic_load_explicit(&e->t_lo, memory_order_relaxed);
    out->t_hi         = atomic_load_explicit(&e->t_hi, memory_order_relaxed);
    out->eta_max_fp16 = atomic_load_explicit(&e->eta_max_fp16, memory_order_relaxed);
    out->src_count    = atomic_load_explicit(&e->src_count, memory_order_relaxed);
    out->quarantine   = atomic_load_explicit(&e->quarantine, memory_order_relaxed);
    out->first_seen   = atomic_load_explicit(&e->first_seen,
                                             memory_order_relaxed);
    out->entity_hash  = atomic_load_explicit(&e->entity_hash,
                                             memory_order_relaxed);
    /* budget[] and the ident[] blob are single-writer-mutated as plain (non-
     * atomic) memory. A concurrent reader must not touch them: the ident bytes
     * are left zeroed here. The caller identifies the entity by entity_hash
     * (its own reverse map holds the readable key); ident[] is only for an
     * offline, quiescent dump. */

    /* Re-check the generation: if the slot was reclaimed between the key_hash
     * load and here, refuse the snapshot rather than return a spliced edge. */
    if (atomic_load_explicit(&e->key_hash, memory_order_acquire) != kh)
        return false;
    return true;
}

uint32_t
wake_tac_iterate(const wake_tac_t *t, wake_tac_iter_fn fn, void *ctx)
{
    uint32_t seen = 0;
    for (uint32_t i = 0; i < t->header->capacity; i++) {
        wake_tac_entry_t snap;
        if (!wake_tac_read_entry(t, i, &snap))
            continue;
        seen++;
        if (!fn(&snap, ctx))
            break;
    }
    return seen;
}

void
wake_tac_stats(const wake_tac_t *t, wake_tac_stats_t *out)
{
    memset(out, 0, sizeof(*out));
    out->capacity = t->header->capacity;

    for (uint32_t i = 0; i < t->header->capacity; i++) {
        const wake_tac_entry_t *e = &t->entries[i];
        uint64_t kh = atomic_load_explicit(&e->key_hash, memory_order_relaxed);
        if (kh == WAKE_TAC_SLOT_EMPTY)
            continue;
        if (kh == WAKE_TAC_SLOT_TOMBSTONE) {
            out->tombstones++;
            continue;
        }
        out->occupied++;
        out->total_weight += atomic_load_explicit(&e->weight,
                                                  memory_order_relaxed);
        if (atomic_load_explicit(&e->quarantine, memory_order_relaxed))
            out->quarantined++;
    }
    for (uint32_t i = 0; i < t->header->occ_slots; i++) {
        const wake_tac_occ_t *o = &t->occ[i];
        if (atomic_load_explicit(&o->entity_hash, memory_order_relaxed) == 0)
            continue;
        if (atomic_load_explicit(&o->live_count, memory_order_relaxed) >=
            t->header->per_entity_cap)
            out->entities_at_cap++;
    }
}
