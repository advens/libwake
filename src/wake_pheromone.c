/*
 * wake_pheromone.c: WAKE Pheromone Table Implementation
 *
 * Copyright (c) 2026 Advens. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "wake_pheromone.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

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

static inline uint32_t
relative_time(const wake_pheromone_t *pt)
{
    return current_epoch_seconds() - pt->header->epoch;
}

static inline size_t
compute_map_size(uint32_t capacity)
{
    return sizeof(wake_pheromone_header_t)
         + (size_t)capacity * sizeof(wake_pheromone_entry_t);
}

/*
 * Compute key_hash for an entity, avoiding sentinel values.
 */
static inline uint64_t
entity_key_hash(const wake_entity_t *entity)
{
    uint64_t h = wake_entity_hash(entity);
    if (h == WAKE_PHT_SLOT_EMPTY || h == WAKE_PHT_SLOT_TOMBSTONE)
        h ^= UINT64_C(0x1);
    return h;
}

/*
 * Internal deposit/reinforce with configurable src_count behavior.
 */
static uint32_t
pht_insert(wake_pheromone_t *pt,
           const wake_entity_t *entity,
           wake_action_t action,
           wake_outcome_t outcome,
           uint32_t tenant_id,
           uint32_t confidence_delta,
           bool increment_src,
           uint32_t phase_flags)
{
    uint64_t key = entity_key_hash(entity);
    uint64_t base = key & pt->header->mask;
    uint32_t now = relative_time(pt);

    uint64_t first_available = UINT64_MAX;

    /* Probe loop: find existing entry or first available slot */
    for (uint32_t probe = 0; probe < WAKE_PHT_PROBE_MAX; probe++) {
        uint64_t idx = (base + probe) & pt->header->mask;
        wake_pheromone_entry_t *e = &pt->entries[idx];

        uint64_t existing = atomic_load_explicit(&e->key_hash,
                                                  memory_order_acquire);

        if (existing == key) {
            /* Found: atomic update on hot fields (cache line 0 only) */
            uint32_t new_conf = atomic_fetch_add_explicit(
                &e->confidence, confidence_delta,
                memory_order_relaxed) + confidence_delta;
            atomic_fetch_add_explicit(&e->hit_count, 1,
                                      memory_order_relaxed);
            atomic_store_explicit(&e->last_update, now,
                                  memory_order_relaxed);
            if (increment_src) {
                atomic_fetch_add_explicit(&e->src_count, 1,
                                          memory_order_relaxed);
            }
            if (phase_flags)
                atomic_fetch_or_explicit(&e->phase_flags, phase_flags,
                                         memory_order_relaxed);
            return new_conf;
        }

        if (existing == WAKE_PHT_SLOT_EMPTY ||
            existing == WAKE_PHT_SLOT_TOMBSTONE) {
            if (first_available == UINT64_MAX)
                first_available = idx;
            if (existing == WAKE_PHT_SLOT_EMPTY)
                break; /* end of probe chain */
        }
    }

    /* Not found: try to insert at first available slot */
    if (first_available == UINT64_MAX)
        return 0; /* table full in probe range */

    wake_pheromone_entry_t *e = &pt->entries[first_available];
    uint64_t expected = atomic_load_explicit(&e->key_hash,
                                              memory_order_relaxed);

    /* Verify slot is still available */
    if (expected != WAKE_PHT_SLOT_EMPTY &&
        expected != WAKE_PHT_SLOT_TOMBSTONE)
        return 0; /* lost race */

    /* CAS to claim the slot */
    if (!atomic_compare_exchange_strong_explicit(
            &e->key_hash, &expected, key,
            memory_order_acq_rel, memory_order_relaxed)) {
        if (expected == key) {
            /* Another thread inserted the same entity: just deposit */
            uint32_t new_conf = atomic_fetch_add_explicit(
                &e->confidence, confidence_delta,
                memory_order_relaxed) + confidence_delta;
            atomic_fetch_add_explicit(&e->hit_count, 1,
                                      memory_order_relaxed);
            atomic_store_explicit(&e->last_update, now,
                                  memory_order_relaxed);
            if (increment_src) {
                atomic_fetch_add_explicit(&e->src_count, 1,
                                          memory_order_relaxed);
            }
            if (phase_flags)
                atomic_fetch_or_explicit(&e->phase_flags, phase_flags,
                                         memory_order_relaxed);
            return new_conf;
        }
        return 0; /* different entity claimed slot */
    }

    /*
     * Slot claimed. Write entity under seqlock.
     *
     * Between the CAS above and the seqlock completion below, concurrent
     * readers may see key_hash match but entity data is stale. This is
     * safe because:
     *   - Hot-path readers only access cache line 0 (confidence etc.)
     *   - Cold-path readers use the seqlock and will retry
     *   - confidence is 0 until we set it below, so the entry is
     *     effectively invisible to threshold checks
     */
    uint32_t ver = atomic_load_explicit(&e->version, memory_order_relaxed);
    uint32_t write_ver = (ver + 1) | 1u; /* next odd = write-lock */
    atomic_store_explicit(&e->version, write_ver, memory_order_release);

    /* Write cold fields (entity, action, outcome, tenant) */
    memcpy((void *)&e->entity, entity, sizeof(wake_entity_t));
    e->action    = (uint8_t)action;
    e->outcome   = (uint8_t)outcome;
    e->first_seen = now;
    e->tenant_id = tenant_id;

    /* Release seqlock: next even version */
    atomic_store_explicit(&e->version, write_ver + 1, memory_order_release);

    /* Set initial atomic fields (after seqlock, as these are independent) */
    atomic_store_explicit(&e->confidence, confidence_delta,
                          memory_order_relaxed);
    atomic_store_explicit(&e->hit_count, 1, memory_order_relaxed);
    atomic_store_explicit(&e->last_update, now, memory_order_relaxed);
    atomic_store_explicit(&e->src_count, 1, memory_order_relaxed);
    atomic_store_explicit(&e->phase_flags, phase_flags,
                          memory_order_relaxed);

    return confidence_delta;
}

/* =========================================================================
 * Table lifecycle
 * ========================================================================= */

wake_pheromone_t *
wake_pheromone_create(const char *path, const wake_pheromone_config_t *cfg)
{
    uint32_t capacity = cfg && cfg->capacity ? cfg->capacity
                                             : WAKE_PHT_DEFAULT_CAPACITY;
    uint32_t decay    = cfg && cfg->decay_factor_fp16 ? cfg->decay_factor_fp16
                                                      : WAKE_PHT_DEFAULT_DECAY_FP16;
    uint32_t floor    = cfg && cfg->noise_floor ? cfg->noise_floor
                                                : WAKE_PHT_DEFAULT_NOISE_FLOOR;

    if (!is_power_of_2(capacity)) {
        errno = EINVAL;
        return NULL;
    }

    size_t map_size = compute_map_size(capacity);

    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (fd < 0)
        return NULL;

    /* Extend file to required size */
    if (ftruncate(fd, (off_t)map_size) < 0) {
        close(fd);
        return NULL;
    }

    /* mmap with MAP_SHARED for cross-process visibility */
    void *base = mmap(NULL, map_size, PROT_READ | PROT_WRITE,
                       MAP_SHARED, fd, 0);
    if (base == MAP_FAILED) {
        close(fd);
        return NULL;
    }

    /* Zero entire region (entries start as empty) */
    memset(base, 0, map_size);

    /* Initialize header */
    wake_pheromone_header_t *hdr = (wake_pheromone_header_t *)base;
    hdr->magic          = WAKE_PHT_MAGIC;
    hdr->format_version = WAKE_PHT_VERSION;
    hdr->capacity       = capacity;
    hdr->mask           = (uint64_t)(capacity - 1);
    hdr->epoch          = current_epoch_seconds();
    hdr->decay_factor_fp16 = decay;
    hdr->noise_floor    = floor;

    /* Generate random SipHash key */
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

    /* Set global hash key so wake_entity_hash() is consistent */
    wake_hash_set_key(hdr->hash_key);

    /* Sync header to disk */
    msync(base, sizeof(wake_pheromone_header_t), MS_SYNC);

    /* Build handle */
    wake_pheromone_t *pt = malloc(sizeof(wake_pheromone_t));
    if (!pt) {
        munmap(base, map_size);
        close(fd);
        return NULL;
    }

    pt->header   = hdr;
    pt->entries  = (wake_pheromone_entry_t *)((char *)base +
                    sizeof(wake_pheromone_header_t));
    pt->map_base = base;
    pt->map_size = map_size;
    pt->fd       = fd;

    return pt;
}

wake_pheromone_t *
wake_pheromone_open(const char *path)
{
    int fd = open(path, O_RDWR);
    if (fd < 0)
        return NULL;

    /* Read header to get capacity */
    wake_pheromone_header_t tmp_hdr;
    ssize_t n = read(fd, &tmp_hdr, sizeof(tmp_hdr));
    if (n != (ssize_t)sizeof(tmp_hdr)) {
        close(fd);
        errno = EIO;
        return NULL;
    }

    /* Validate */
    if (tmp_hdr.magic != WAKE_PHT_MAGIC) {
        close(fd);
        errno = EINVAL;
        return NULL;
    }
    if (tmp_hdr.format_version != WAKE_PHT_VERSION) {
        close(fd);
        errno = EINVAL;
        return NULL;
    }
    if (!is_power_of_2(tmp_hdr.capacity)) {
        close(fd);
        errno = EINVAL;
        return NULL;
    }

    size_t map_size = compute_map_size(tmp_hdr.capacity);

    /* Verify file size */
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

    wake_pheromone_header_t *hdr = (wake_pheromone_header_t *)base;

    /* Set global hash key for entity hashing consistency */
    wake_hash_set_key(hdr->hash_key);

    wake_pheromone_t *pt = malloc(sizeof(wake_pheromone_t));
    if (!pt) {
        munmap(base, map_size);
        close(fd);
        return NULL;
    }

    pt->header   = hdr;
    pt->entries  = (wake_pheromone_entry_t *)((char *)base +
                    sizeof(wake_pheromone_header_t));
    pt->map_base = base;
    pt->map_size = map_size;
    pt->fd       = fd;

    return pt;
}

void
wake_pheromone_close(wake_pheromone_t *pt)
{
    if (!pt)
        return;
    if (pt->map_base && pt->map_base != MAP_FAILED)
        munmap(pt->map_base, pt->map_size);
    if (pt->fd >= 0)
        close(pt->fd);
    free(pt);
}

/* =========================================================================
 * Hot-path operations
 * ========================================================================= */

uint32_t
wake_pheromone_deposit(wake_pheromone_t *pt,
                       const wake_entity_t *entity,
                       wake_action_t action,
                       wake_outcome_t outcome,
                       uint32_t tenant_id,
                       uint32_t confidence_delta,
                       uint32_t phase_flags)
{
    return pht_insert(pt, entity, action, outcome, tenant_id,
                      confidence_delta, false, phase_flags);
}

uint32_t
wake_pheromone_lookup(const wake_pheromone_t *pt,
                      const wake_entity_t *entity)
{
    uint64_t key = entity_key_hash(entity);
    uint64_t base = key & pt->header->mask;

    for (uint32_t probe = 0; probe < WAKE_PHT_PROBE_MAX; probe++) {
        uint64_t idx = (base + probe) & pt->header->mask;
        const wake_pheromone_entry_t *e = &pt->entries[idx];

        uint64_t existing = atomic_load_explicit(&e->key_hash,
                                                  memory_order_acquire);

        if (existing == key) {
            return atomic_load_explicit(&e->confidence,
                                        memory_order_relaxed);
        }

        if (existing == WAKE_PHT_SLOT_EMPTY)
            return 0; /* end of probe chain, not found */

        /* TOMBSTONE or different key: continue probing */
    }

    return 0; /* probe exhausted */
}

uint32_t
wake_pheromone_reinforce(wake_pheromone_t *pt,
                         const wake_entity_t *entity,
                         wake_action_t action,
                         wake_outcome_t outcome,
                         uint32_t tenant_id,
                         uint32_t confidence_delta,
                         uint32_t phase_flags)
{
    return pht_insert(pt, entity, action, outcome, tenant_id,
                      confidence_delta, true, phase_flags);
}

bool
wake_pheromone_remove(wake_pheromone_t *pt,
                      const wake_entity_t *entity)
{
    uint64_t key = entity_key_hash(entity);
    uint64_t base = key & pt->header->mask;

    for (uint32_t probe = 0; probe < WAKE_PHT_PROBE_MAX; probe++) {
        uint64_t idx = (base + probe) & pt->header->mask;
        wake_pheromone_entry_t *e = &pt->entries[idx];

        uint64_t existing = atomic_load_explicit(&e->key_hash,
                                                  memory_order_acquire);

        if (existing == key) {
            /* Tombstone the entry */
            uint64_t expected = key;
            return atomic_compare_exchange_strong_explicit(
                &e->key_hash, &expected, WAKE_PHT_SLOT_TOMBSTONE,
                memory_order_acq_rel, memory_order_relaxed);
        }

        if (existing == WAKE_PHT_SLOT_EMPTY)
            return false;
    }

    return false;
}

/* =========================================================================
 * Maintenance: decay
 * ========================================================================= */

uint32_t
wake_pheromone_decay(wake_pheromone_t *pt)
{
    uint32_t capacity     = pt->header->capacity;
    uint32_t decay_factor = pt->header->decay_factor_fp16;
    uint32_t noise_floor  = pt->header->noise_floor;
    uint32_t evicted      = 0;

    for (uint32_t i = 0; i < capacity; i++) {
        wake_pheromone_entry_t *e = &pt->entries[i];

        uint64_t kh = atomic_load_explicit(&e->key_hash,
                                            memory_order_relaxed);

        if (kh == WAKE_PHT_SLOT_EMPTY || kh == WAKE_PHT_SLOT_TOMBSTONE)
            continue;

        /* Read current confidence */
        uint32_t old_conf = atomic_load_explicit(&e->confidence,
                                                  memory_order_relaxed);

        /* Apply decay: new = (old * factor) >> 16 */
        uint32_t new_conf = (uint32_t)(((uint64_t)old_conf * decay_factor)
                                        >> 16);

        if (new_conf < noise_floor) {
            /* Evict: tombstone the entry */
            uint64_t expected = kh;
            if (atomic_compare_exchange_strong_explicit(
                    &e->key_hash, &expected, WAKE_PHT_SLOT_TOMBSTONE,
                    memory_order_acq_rel, memory_order_relaxed)) {
                evicted++;
            }
        } else {
            /* Decay: CAS confidence to new value */
            atomic_compare_exchange_strong_explicit(
                &e->confidence, &old_conf, new_conf,
                memory_order_relaxed, memory_order_relaxed);
            /*
             * If CAS fails (concurrent deposit changed confidence),
             * skip this cycle. The next decay will catch it.
             * Acceptable for a probabilistic system.
             */
        }
    }

    return evicted;
}

/* =========================================================================
 * Cold-path reads
 * ========================================================================= */

bool
wake_pheromone_read_entry(const wake_pheromone_t *pt,
                          uint32_t slot_index,
                          wake_pheromone_entry_t *out)
{
    if (slot_index >= pt->header->capacity)
        return false;

    const wake_pheromone_entry_t *e = &pt->entries[slot_index];

    uint64_t kh = atomic_load_explicit(&e->key_hash,
                                        memory_order_acquire);
    if (kh == WAKE_PHT_SLOT_EMPTY || kh == WAKE_PHT_SLOT_TOMBSTONE)
        return false;

    /*
     * Seqlock read: spin until we get a consistent snapshot.
     * The version field is odd during writes.
     */
    for (;;) {
        uint32_t v1 = atomic_load_explicit(&e->version,
                                            memory_order_acquire);
        if (v1 & 1u) {
            /* Entry being written; yield and retry */
#if defined(__aarch64__)
            __asm__ volatile("yield" ::: "memory");
#elif defined(__x86_64__)
            __asm__ volatile("pause" ::: "memory");
#endif
            continue;
        }

        /* Read all fields */
        out->key_hash = atomic_load_explicit(&e->key_hash,
                                              memory_order_relaxed);
        out->confidence = atomic_load_explicit(&e->confidence,
                                                memory_order_relaxed);
        out->hit_count = atomic_load_explicit(&e->hit_count,
                                               memory_order_relaxed);
        out->last_update = atomic_load_explicit(&e->last_update,
                                                 memory_order_relaxed);
        out->src_count = atomic_load_explicit(&e->src_count,
                                               memory_order_relaxed);
        out->action    = e->action;
        out->outcome   = e->outcome;
        out->first_seen = e->first_seen;
        out->tenant_id = e->tenant_id;
        out->phase_flags = atomic_load_explicit(&e->phase_flags,
                                                 memory_order_relaxed);
        memcpy((void *)&out->entity, (const void *)&e->entity,
               sizeof(wake_entity_t));

        /* Verify consistency */
        atomic_thread_fence(memory_order_acquire);
        uint32_t v2 = atomic_load_explicit(&e->version,
                                            memory_order_relaxed);

        if (v1 == v2) {
            out->version = v1;
            return true;
        }
        /* Version changed during read: retry */
    }
}

uint32_t
wake_pheromone_iterate(const wake_pheromone_t *pt,
                       wake_pheromone_iter_fn fn, void *ctx)
{
    uint32_t visited = 0;

    for (uint32_t i = 0; i < pt->header->capacity; i++) {
        wake_pheromone_entry_t snap;
        if (wake_pheromone_read_entry(pt, i, &snap)) {
            visited++;
            if (!fn(&snap, ctx))
                break;
        }
    }

    return visited;
}

/* =========================================================================
 * Statistics
 * ========================================================================= */

void
wake_pheromone_stats(const wake_pheromone_t *pt,
                     wake_pheromone_stats_t *out)
{
    memset(out, 0, sizeof(*out));
    out->capacity = pt->header->capacity;

    for (uint32_t i = 0; i < pt->header->capacity; i++) {
        uint64_t kh = atomic_load_explicit(&pt->entries[i].key_hash,
                                            memory_order_relaxed);

        if (kh == WAKE_PHT_SLOT_EMPTY)
            continue;

        if (kh == WAKE_PHT_SLOT_TOMBSTONE) {
            out->tombstones++;
            continue;
        }

        out->occupied++;
        out->total_confidence += atomic_load_explicit(
            &pt->entries[i].confidence, memory_order_relaxed);

        /* Compute probe length for this entry */
        uint64_t home = kh & pt->header->mask;
        uint32_t probe_len;
        if (i >= home)
            probe_len = (uint32_t)(i - home);
        else
            probe_len = (uint32_t)(pt->header->capacity - home + i);

        if (probe_len > out->max_probe_len)
            out->max_probe_len = probe_len;
    }
}
