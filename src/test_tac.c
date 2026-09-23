/*
 * test_tac.c: wake_tac invariant tests
 *
 * Synthetic activation streams only. No mesh, no real clock:
 * every case drives its own `now` counter. One table file per case.
 *
 * Copyright (c) 2026 Advens. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "wake_tac.h"

#include <stdio.h>
#include <string.h>

/* Fidelity-tier eta weights (0.16 fixed point), as used by the host application. */
#define ETA_CONFIRMED 65535u
#define ETA_STRONG    39321u
#define ETA_WEAK      19661u
#define ETA_CONTEXT    6554u

static int g_fail;

#define CHECK(cond)                                                           \
    do {                                                                      \
        if (!(cond)) {                                                        \
            printf("  FAIL %s:%d  %s\n", __func__, __LINE__, #cond);          \
            g_fail = 1;                                                       \
            return 1;                                                         \
        }                                                                     \
    } while (0)

static wake_tac_t *
mk(const char *name, uint16_t cap, uint16_t corr_min, uint32_t budget)
{
    char path[256];
    snprintf(path, sizeof(path), "/tmp/tac_test_%s.dat", name);
    wake_tac_config_t cfg = {0};
    cfg.per_entity_cap = cap;
    cfg.corroboration_src_min = corr_min;
    cfg.budget_per_source = budget;
    return wake_tac_create(path, &cfg);
}

static const uint8_t *E(const char *s, size_t *len)
{
    *len = strlen(s);
    return (const uint8_t *)s;
}

static uint32_t
mass_of(wake_tac_t *t, const char *ekey)
{
    size_t l;
    const uint8_t *e = E(ekey, &l);
    wake_tac_snapshot_t s;
    if (!wake_tac_query(t, e, l, &s))
        return 0;
    return s.coupling_mass;
}

static uint32_t
edges_of(wake_tac_t *t, const char *ekey)
{
    size_t l;
    const uint8_t *e = E(ekey, &l);
    wake_tac_snapshot_t s;
    if (!wake_tac_query(t, e, l, &s))
        return 0;
    return s.edge_count;
}

/* -------------------------------------------------------------------------- */

/* Reinforce raises w>0; one decay lowers every live w or tombstones;
 *    w<noise_floor tombstones and occupancy drops; a one-source pair loses
 *    more per decay than the same pair once a 2nd distinct STRONG source
 *    has hit (novel vs corroborated rate). */
static int test_reinforce_and_decay(void)
{
    wake_tac_t *t = mk("reinforce", 8, 2, 20000);
    CHECK(t);
    size_t l;
    const uint8_t *e = E("h1|u1", &l);
    uint32_t A = wake_tac_pack(1071, 0), B = wake_tac_pack(1041, 0);

    CHECK(wake_tac_reinforce(t, e, l, A, B, ETA_WEAK, 10, 0) == WAKE_TAC_APPLIED);
    uint32_t w0 = mass_of(t, "h1|u1");
    CHECK(w0 > 0);

    /* novel decay: single WEAK source, run ticks, measure the drop */
    wake_tac_decay(t);
    uint32_t w_novel = mass_of(t, "h1|u1");
    CHECK(w_novel < w0);
    uint32_t drop_novel = w0 - w_novel;

    /* add a 2nd distinct STRONG source -> corroborated */
    CHECK(wake_tac_reinforce(t, e, l, A, B, ETA_STRONG, 20, 0) == WAKE_TAC_APPLIED);
    uint32_t w1 = mass_of(t, "h1|u1");
    wake_tac_decay(t);
    uint32_t w_corr = mass_of(t, "h1|u1");
    CHECK(w_corr < w1);
    uint32_t drop_corr = w1 - w_corr;

    /* Corroborated decays strictly slower PER UNIT WEIGHT. Cross-multiplied to
     * stay in integers: drop_corr/w1 < drop_novel/w0. No disjunct escape; a
     * regression that made both rates equal must fail here. */
    CHECK((uint64_t)drop_corr * w0 < (uint64_t)drop_novel * w1);

    /* run to floor -> tombstone + occupancy zero */
    for (int i = 0; i < 5000 && edges_of(t, "h1|u1") > 0; i++)
        wake_tac_decay(t);
    CHECK(edges_of(t, "h1|u1") == 0);
    wake_tac_stats_t st;
    wake_tac_stats(t, &st);
    CHECK(st.occupied == 0);

    wake_tac_close(t);
    return 0;
}

/* Reinforce on E1 does not change query(E2); the API has no entity-less
 *    or tenant-global write. */
static int test_edge_local_writes(void)
{
    wake_tac_t *t = mk("edgelocal", 8, 2, 20000);
    CHECK(t);
    size_t l1, l2;
    const uint8_t *e1 = E("host-a|svc", &l1);
    const uint8_t *e2 = E("host-b|svc", &l2);
    uint32_t A = wake_tac_pack(1046, 0), B = wake_tac_pack(1071, 0);

    wake_tac_reinforce(t, e1, l1, A, B, ETA_STRONG, 1, 0);
    CHECK(mass_of(t, "host-b|svc") == 0);
    CHECK(edges_of(t, "host-b|svc") == 0);

    wake_tac_reinforce(t, e2, l2, A, B, ETA_STRONG, 1, 0);
    CHECK(mass_of(t, "host-a|svc") == mass_of(t, "host-b|svc"));
    wake_tac_close(t);
    return 0;
}

/* A snapshot carries no baked verdict; a query never mutates the weight;
 *    the same weight yields the same mass, and an external threshold is
 *    what decides. */
static int test_snapshot_no_verdict(void)
{
    /* compile-time: the struct has exactly these members */
    CHECK(sizeof(wake_tac_snapshot_t) ==
          sizeof(uint32_t) * 3 +
          sizeof(wake_tac_edge_t) * WAKE_TAC_QUERY_TOP_MAX);

    wake_tac_t *t = mk("noverdict", 8, 2, 20000);
    CHECK(t);
    size_t l;
    const uint8_t *e = E("q|r", &l);
    uint32_t A = wake_tac_pack(1071, 0), B = wake_tac_pack(1041, 0),
             C = wake_tac_pack(1059, 1);
    wake_tac_activation_t acts[3] = {
        {A, ETA_STRONG, 1}, {B, ETA_STRONG, 2}, {C, ETA_WEAK, 3}
    };
    wake_tac_reinforce_batch(t, e, l, acts, 3, 0);

    uint32_t before = mass_of(t, "q|r");
    wake_tac_input_t out[3];
    uint32_t n = wake_tac_route(t, e, l, acts, 3, out, 3);
    CHECK(n == 3);
    CHECK(mass_of(t, "q|r") == before);   /* route is a pure read */

    /* No verdict lives in the snapshot: the caller's threshold decides. The
     * joint strength of a pair is its weaker leg, so: (STRONG,STRONG)->2457,
     * (STRONG,WEAK)->1228, (STRONG,WEAK)->1228 => mass 4913. Two fixed
     * policies, one below and one above, must disagree; C returns the same
     * number to both. */
    uint32_t m = mass_of(t, "q|r");
    uint32_t expect = ((uint32_t)ETA_STRONG >> 4) + 2u * ((uint32_t)ETA_WEAK >> 4);
    CHECK(m == expect);
    const uint32_t LOOSE = 1000, TIGHT = 10000;
    CHECK((m > LOOSE) == 1);
    CHECK((m > TIGHT) == 0);
    CHECK(mass_of(t, "q|r") == m);        /* querying twice never mutates W */
    wake_tac_close(t);
    return 0;
}

/* Time is epoch-relative: two tables with different epochs driven by the
 *    same call counts hold equal weights; decay uses no wall clock. */
static int test_epoch_relative_clock(void)
{
    wake_tac_t *a = mk("epocha", 8, 2, 20000);
    wake_tac_t *b = mk("epochb", 8, 2, 20000);
    CHECK(a && b);
    size_t l;
    const uint8_t *e = E("x|y", &l);
    uint32_t T1 = wake_tac_pack(1071, 0), T2 = wake_tac_pack(1041, 0);

    for (uint32_t now = 0; now < 20; now++) {
        wake_tac_reinforce(a, e, l, T1, T2, ETA_STRONG, 1, now);
        wake_tac_reinforce(b, e, l, T1, T2, ETA_STRONG, 1, now + 1000000);
    }
    for (int i = 0; i < 30; i++) {
        wake_tac_decay(a);
        wake_tac_decay(b);
    }
    CHECK(mass_of(a, "x|y") == mass_of(b, "x|y"));
    wake_tac_close(a);
    wake_tac_close(b);
    return 0;
}

/* Mass is force, not semantics: two edges of equal weight yield equal
 *    mass regardless of which technique numbers label them. */
static int test_mass_is_force_not_semantics(void)
{
    wake_tac_t *t = mk("force", 8, 9, 20000);   /* corr_min high: keep both novel */
    CHECK(t);
    size_t l1, l2;
    const uint8_t *e1 = E("k1", &l1);
    const uint8_t *e2 = E("k2", &l2);

    /* e1: a "scan->c2" shaped pair; e2: a "brute->valid-accounts" pair */
    wake_tac_reinforce(t, e1, l1, wake_tac_pack(1046, 0), wake_tac_pack(1071, 0),
                       ETA_STRONG, 1, 0);
    wake_tac_reinforce(t, e2, l2, wake_tac_pack(1110, 0), wake_tac_pack(1078, 0),
                       ETA_STRONG, 1, 0);
    CHECK(mass_of(t, "k1") == mass_of(t, "k2"));
    CHECK(edges_of(t, "k1") == 1 && edges_of(t, "k2") == 1);
    wake_tac_close(t);
    return 0;
}

/* Masking: adding WEAK/CONTEXT activations on the same entity does not
 *      lower a CONFIRMED-cross-CONFIRMED edge's query mass (mass is a sum of
 *      force, not an entropy). */
static int test_masking_does_not_lower_mass(void)
{
    wake_tac_t *t = mk("masking", 16, 2, 20000);
    CHECK(t);
    size_t l;
    const uint8_t *e = E("victim|adm", &l);
    uint32_t MAL_A = wake_tac_pack(1003, 0), MAL_B = wake_tac_pack(1048, 3);

    wake_tac_reinforce(t, e, l, MAL_A, MAL_B, ETA_CONFIRMED, 100, 0);
    wake_tac_reinforce(t, e, l, MAL_B, MAL_A, ETA_CONFIRMED, 200, 0);
    uint32_t mal_mass_before = 0;
    {
        wake_tac_snapshot_t s;
        wake_tac_query(t, e, l, &s);
        for (uint32_t i = 0; i < s.top_count; i++)
            if ((s.top[i].t_lo == MAL_A && s.top[i].t_hi == MAL_B) ||
                (s.top[i].t_lo == MAL_B && s.top[i].t_hi == MAL_A))
                mal_mass_before = s.top[i].weight;
    }
    CHECK(mal_mass_before > 0);

    /* flood the entity with benign WEAK/CONTEXT co-activations */
    for (int i = 0; i < 40; i++) {
        wake_tac_activation_t noise[3] = {
            {wake_tac_pack((uint16_t)(2000 + i), 0), ETA_WEAK, (uint16_t)(300 + i)},
            {wake_tac_pack((uint16_t)(2500 + i), 0), ETA_CONTEXT, (uint16_t)(400 + i)},
            {wake_tac_pack((uint16_t)(2600 + i), 0), ETA_CONTEXT, (uint16_t)(500 + i)},
        };
        wake_tac_reinforce_batch(t, e, l, noise, 3, 0);
    }

    uint32_t mal_mass_after = 0;
    {
        wake_tac_snapshot_t s;
        wake_tac_query(t, e, l, &s);
        for (uint32_t i = 0; i < s.top_count; i++)
            if ((s.top[i].t_lo == MAL_A && s.top[i].t_hi == MAL_B) ||
                (s.top[i].t_lo == MAL_B && s.top[i].t_hi == MAL_A))
                mal_mass_after = s.top[i].weight;
    }
    CHECK(mal_mass_after >= mal_mass_before);   /* not washed out */
    wake_tac_close(t);
    return 0;
}

/* A single-source WEAK-spammed edge never corroborates (src_count stays 1),
 *      so it decays at the novel rate and fades below a CONFIRMED-cross-CONFIRMED
 *      two-source edge that earns the corroborated rate. Sustained presence from
 *      one source does not buy durable memory. */
static int test_weak_weak_decays_faster(void)
{
    wake_tac_t *t = mk("weakweak", 8, 2, 20000);
    CHECK(t);
    size_t l1, l2;
    const uint8_t *w = E("weakpair", &l1);
    const uint8_t *c = E("confpair", &l2);
    uint32_t A = wake_tac_pack(1071, 0), B = wake_tac_pack(1041, 0);

    for (int i = 0; i < 200; i++)
        wake_tac_reinforce(t, w, l1, A, B, ETA_WEAK, 1, (uint32_t)i);
    wake_tac_reinforce(t, c, l2, A, B, ETA_CONFIRMED, 1, 0);
    wake_tac_reinforce(t, c, l2, A, B, ETA_CONFIRMED, 2, 0);

    /* The WEAK-spam edge is single-source, so it is BOTH uncorroborated (fast
     * decay) and outlier-quarantined (excluded from mass). Either way it must
     * not out-mass the two-source CONFIRMED edge. */
    CHECK(mass_of(t, "weakpair") < mass_of(t, "confpair"));

    for (int i = 0; i < 60; i++)
        wake_tac_decay(t);
    CHECK(mass_of(t, "weakpair") < mass_of(t, "confpair"));
    wake_tac_close(t);
    return 0;
}

/* Outlier-reinforcement quarantine: a single source dominating an edge past the floor
 *      trips quarantine (edge drops out of mass, that source is refused);
 *      a genuinely new distinct source clears it. */
static int test_outlier_quarantine(void)
{
    wake_tac_t *t = mk("quarantine", 8, 2, 60000);
    CHECK(t);
    size_t l;
    const uint8_t *e = E("solo|e", &l);
    uint32_t A = wake_tac_pack(1071, 0), B = wake_tac_pack(1041, 0);

    /* one source, sustained -> dominates its own edge */
    int quarantined = 0;
    for (int i = 0; i < 40; i++) {
        wake_tac_result_t r =
            wake_tac_reinforce(t, e, l, A, B, ETA_CONFIRMED, 7, (uint32_t)i);
        if (r == WAKE_TAC_REFUSED_QUARANTINE) {
            quarantined = 1;
            break;
        }
    }
    CHECK(quarantined);

    /* quarantined edge is excluded from query mass */
    CHECK(mass_of(t, "solo|e") == 0);

    /* the entry still exists and still carries the flag */
    {
        wake_tac_stats_t st;
        wake_tac_stats(t, &st);
        CHECK(st.quarantined == 1);
        CHECK(st.occupied == 1);
    }

    /* an independent second source is allowed through and clears it */
    CHECK(wake_tac_reinforce(t, e, l, A, B, ETA_STRONG, 9, 100) ==
          WAKE_TAC_APPLIED);
    CHECK(mass_of(t, "solo|e") > 0);
    {
        wake_tac_stats_t st;
        wake_tac_stats(t, &st);
        CHECK(st.quarantined == 0);
    }
    wake_tac_close(t);
    return 0;
}

/* The per-entity cap must hold even when the occupancy sidecar is at its
 * tightest legal load (occ_slots == capacity, every slot an entity). The
 * `occ_slots >= capacity` guarantee means occ can never be more loaded than
 * the main table, so an entity is always trackable; if a claim ever did fail
 * the new edge is REFUSED, never inserted uncapped. */
static int test_occ_pressure_cap_holds(void)
{
    wake_tac_config_t cfg = {0};
    cfg.capacity = 64;
    cfg.occ_slots = 64;             /* tightest legal: == capacity */
    cfg.per_entity_cap = 4;
    cfg.corroboration_src_min = 2;
    cfg.budget_per_source = 60000;
    cfg.quarantine_min_w = UINT32_MAX;
    wake_tac_t *t = wake_tac_create("/tmp/tac_test_occpress.dat", &cfg);
    CHECK(t);

    /* many entities, each pushed well past its cap */
    for (int h = 0; h < 24; h++) {
        char key[32];
        snprintf(key, sizeof(key), "e%d|u", h);
        size_t l;
        const uint8_t *e = E(key, &l);
        for (int p = 0; p < 20; p++)
            wake_tac_reinforce(t, e, l, wake_tac_pack((uint16_t)(10 + p), 0),
                               wake_tac_pack((uint16_t)(90 + p), 0),
                               ETA_STRONG, (uint16_t)(1 + (p % 3)), (uint32_t)p);
        CHECK(edges_of(t, key) <= 4);   /* cap never exceeded */
    }
    wake_tac_close(t);
    return 0;
}

/* Cap eviction must never destroy a live edge without inserting the
 * replacement: with the table full in the new edge's probe window the call
 * returns TABLE_FULL and the entity keeps every edge it had. */
static int test_cap_evict_table_full_keeps_victim(void)
{
    /* tiny capacity so the main-table probe window fills; per-entity cap low so
     * the cap path is reached via occupancy well before the table is full */
    wake_tac_config_t cfg = {0};
    cfg.capacity = 16;
    cfg.occ_slots = 16;   /* must be >= capacity */
    cfg.per_entity_cap = 2;
    cfg.corroboration_src_min = 2;
    cfg.budget_per_source = 60000;
    cfg.quarantine_min_w = UINT32_MAX;   /* off: isolate the cap behaviour */
    wake_tac_t *t = wake_tac_create("/tmp/tac_test_capfull.dat", &cfg);
    CHECK(t);

    size_t l;
    const uint8_t *e = E("tiny|e", &l);

    /* fill the entity to its cap with heavy edges */
    for (int i = 0; i < 2; i++) {
        uint32_t x = wake_tac_pack((uint16_t)(500 + i), 0);
        uint32_t y = wake_tac_pack((uint16_t)(600 + i), 0);
        for (int k = 0; k < 4; k++)
            wake_tac_reinforce(t, e, l, x, y, ETA_CONFIRMED, (uint16_t)(1 + k),
                               0);
    }
    uint32_t edges_before = edges_of(t, "tiny|e");
    CHECK(edges_before == 2);

    /* stuff every other slot with other entities so probe windows are full */
    for (int j = 0; j < 40; j++) {
        char k2[32];
        snprintf(k2, sizeof(k2), "filler%d", j);
        size_t fl;
        const uint8_t *fe = E(k2, &fl);
        wake_tac_reinforce(t, fe, fl, wake_tac_pack((uint16_t)(700 + j), 0),
                           wake_tac_pack((uint16_t)(800 + j), 0),
                           ETA_CONFIRMED, 1, 0);
    }

    /* now push heavy new pairs at the capped entity; whatever the outcome,
     * it must never end up with fewer edges than it had */
    for (int j = 0; j < 40; j++) {
        wake_tac_reinforce(t, e, l, wake_tac_pack((uint16_t)(900 + j), 0),
                           wake_tac_pack((uint16_t)(950 + j), 0),
                           ETA_CONFIRMED, 2, 0);
        CHECK(edges_of(t, "tiny|e") >= edges_before);
    }
    wake_tac_close(t);
    return 0;
}

/* A flood of distinct pairs on one entity caps at
 *      per_entity_cap; a second entity is untouched; stats reflect it. */
static int test_eviction_dos_cap(void)
{
    wake_tac_t *t = mk("evictdos", 32, 2, 20000);
    CHECK(t);
    size_t l1, l2;
    const uint8_t *v = E("floodme", &l1);
    const uint8_t *o = E("other", &l2);

    wake_tac_reinforce(t, o, l2, wake_tac_pack(1, 0), wake_tac_pack(2, 0),
                       ETA_STRONG, 1, 0);

    for (uint32_t i = 0; i < 4000; i++) {
        uint32_t x = wake_tac_pack((uint16_t)(3000 + (i % 200)), 0);
        uint32_t y = wake_tac_pack((uint16_t)(9000 + i), (uint8_t)(i & 7));
        wake_tac_reinforce(t, v, l1, x, y, ETA_STRONG, (uint16_t)(1 + (i % 3)),
                           i);
    }
    CHECK(edges_of(t, "floodme") <= 32);
    CHECK(edges_of(t, "other") == 1);

    wake_tac_stats_t st;
    wake_tac_stats(t, &st);
    CHECK(st.entities_at_cap == 1);
    wake_tac_close(t);
    return 0;
}

/* Replace if stronger: a novel pair at cap does not evict a heavier
 *      corroborated edge; a heavier pair can replace the weakest. */
static int test_replace_if_stronger(void)
{
    wake_tac_t *t = mk("replace", 3, 2, 60000);
    CHECK(t);
    size_t l;
    const uint8_t *e = E("cap3|e", &l);

    /* fill the 3 slots: one heavy corroborated, two light novel */
    uint32_t H1 = wake_tac_pack(100, 0), H2 = wake_tac_pack(101, 0);
    for (int i = 0; i < 6; i++) {
        wake_tac_reinforce(t, e, l, H1, H2, ETA_CONFIRMED, 11, (uint32_t)i);
        wake_tac_reinforce(t, e, l, H1, H2, ETA_CONFIRMED, 12, (uint32_t)i);
    }
    wake_tac_reinforce(t, e, l, wake_tac_pack(200, 0), wake_tac_pack(201, 0),
                       ETA_CONTEXT, 13, 0);
    wake_tac_reinforce(t, e, l, wake_tac_pack(202, 0), wake_tac_pack(203, 0),
                       ETA_CONTEXT, 14, 0);
    CHECK(edges_of(t, "cap3|e") == 3);

    uint32_t heavy_before = 0;
    {
        wake_tac_snapshot_t s;
        wake_tac_query(t, e, l, &s);
        for (uint32_t i = 0; i < s.top_count; i++)
            if (s.top[i].t_lo == H1 && s.top[i].t_hi == H2)
                heavy_before = s.top[i].weight;
    }
    CHECK(heavy_before > 0);

    /* a new CONTEXT pair at cap: must NOT displace the heavy edge */
    wake_tac_reinforce(t, e, l, wake_tac_pack(300, 0), wake_tac_pack(301, 0),
                       ETA_CONTEXT, 15, 0);
    uint32_t heavy_after = 0;
    {
        wake_tac_snapshot_t s;
        wake_tac_query(t, e, l, &s);
        CHECK(s.edge_count == 3);
        for (uint32_t i = 0; i < s.top_count; i++)
            if (s.top[i].t_lo == H1 && s.top[i].t_hi == H2)
                heavy_after = s.top[i].weight;
    }
    CHECK(heavy_after == heavy_before);

    /* a heavy CONFIRMED new pair: may replace the weakest */
    wake_tac_reinforce(t, e, l, wake_tac_pack(400, 0), wake_tac_pack(401, 0),
                       ETA_CONFIRMED, 16, 0);
    CHECK(edges_of(t, "cap3|e") == 3);
    wake_tac_close(t);
    return 0;
}

/* Budget exhaustion: after spent hits budget_per_source, further
 *      reinforces from that source return WAKE_TAC_REFUSED_BUDGET; decay
 *      still runs. */
static int test_per_source_budget_refusal(void)
{
    wake_tac_t *t = mk("budget", 8, 2, 8000);
    CHECK(t);
    size_t l;
    const uint8_t *e = E("b|e", &l);
    uint32_t A = wake_tac_pack(1071, 0), B = wake_tac_pack(1041, 0);

    int refused = 0;
    for (int i = 0; i < 30; i++) {
        wake_tac_result_t r =
            wake_tac_reinforce(t, e, l, A, B, ETA_CONFIRMED, 42, 0);
        if (r == WAKE_TAC_REFUSED_BUDGET) {
            refused = 1;
            break;
        }
        CHECK(r == WAKE_TAC_APPLIED);
    }
    CHECK(refused);

    uint32_t before = mass_of(t, "b|e");
    wake_tac_decay(t);
    CHECK(mass_of(t, "b|e") <= before);   /* decay still applies */
    wake_tac_close(t);
    return 0;
}

/* The shared OTHER bucket: a 5th and 6th distinct source both land in
 *      one budget slot; src_count saturates at WAKE_TAC_BUDGET_SLOTS. */
static int test_shared_other_bucket_saturates(void)
{
    wake_tac_t *t = mk("otherbucket", 8, 2, 20000);
    CHECK(t);
    size_t l;
    const uint8_t *e = E("o|e", &l);
    uint32_t A = wake_tac_pack(1071, 0), B = wake_tac_pack(1041, 0);

    for (uint16_t src = 1; src <= 8; src++)
        wake_tac_reinforce(t, e, l, A, B, ETA_STRONG, src, 0);

    wake_tac_snapshot_t s;
    CHECK(wake_tac_query(t, e, l, &s));
    CHECK(s.top[0].src_count == WAKE_TAC_BUDGET_SLOTS);   /* saturates at 5 */
    wake_tac_close(t);
    return 0;
}

/* occupancy telemetry: a benign-shaped stream (few techniques per entity,
 * well under the cap) keeps stats.entities_at_cap == 0. */
static int test_occupancy_benign(void)
{
    wake_tac_t *t = mk("occ", 32, 2, 20000);
    CHECK(t);
    for (int h = 0; h < 50; h++) {
        char key[32];
        snprintf(key, sizeof(key), "10.0.0.%d|u", h);
        size_t l;
        const uint8_t *e = E(key, &l);
        wake_tac_activation_t acts[3] = {
            {wake_tac_pack(1071, 0), ETA_WEAK, 1},
            {wake_tac_pack(1041, 0), ETA_WEAK, 2},
            {wake_tac_pack(1059, 1), ETA_CONTEXT, 3},
        };
        wake_tac_reinforce_batch(t, e, l, acts, 3, (uint32_t)h);
    }
    wake_tac_stats_t st;
    wake_tac_stats(t, &st);
    CHECK(st.entities_at_cap == 0);
    wake_tac_close(t);
    return 0;
}

/* Gate C simulation: one STRONG source reinforcing every tick plateaus (does
 * not grow unbounded) and clears within a bounded number of decays once it
 * stops; two independent STRONG sources survive materially longer. */
static int test_gate_c_sim(void)
{
    wake_tac_t *t = mk("gatec", 8, 2, 20000);
    CHECK(t);
    size_t l1, l2;
    const uint8_t *one = E("fp-one|e", &l1);
    const uint8_t *two = E("fp-two|e", &l2);
    uint32_t A = wake_tac_pack(1071, 0), B = wake_tac_pack(1041, 0);

    uint32_t peak = 0;
    for (uint32_t tick = 0; tick < 200; tick++) {
        wake_tac_reinforce(t, one, l1, A, B, ETA_STRONG, 1, tick);
        wake_tac_reinforce(t, two, l2, A, B, ETA_STRONG, 1, tick);
        wake_tac_reinforce(t, two, l2, A, B, ETA_STRONG, 2, tick);
        wake_tac_decay(t);
        uint32_t m = mass_of(t, "fp-one|e");
        if (m > peak)
            peak = m;
    }
    /* The single-source FP plateaus at its own budget (20000 force units) and
     * cannot climb past it however long it fires. Pin the actual ceiling, not
     * a slack multiple of it: 200 STRONG ticks unbudgeted would reach ~490k. */
    CHECK(peak <= 20000);

    /* stop feeding; count decays to floor for each */
    int d_one = 0, d_two = 0;
    for (int i = 0; i < 100000 && edges_of(t, "fp-one|e") > 0; i++) {
        wake_tac_decay(t);
        d_one++;
    }
    for (int i = 0; i < 100000 && edges_of(t, "fp-two|e") > 0; i++) {
        wake_tac_decay(t);
        d_two++;
    }
    CHECK(edges_of(t, "fp-one|e") == 0);
    CHECK(d_two > d_one);   /* corroborated survives longer */
    wake_tac_close(t);
    return 0;
}

/* lifecycle: bad config rejected; open round-trips; reset empties. */
static int test_lifecycle(void)
{
    wake_tac_config_t bad = {0};
    bad.budget_per_source = 100;   /* below WAKE_TAC_DELTA_MAX */
    CHECK(wake_tac_create("/tmp/tac_test_bad.dat", &bad) == NULL);
    bad.budget_per_source = 20000;
    bad.capacity = 1000;           /* not a power of two */
    CHECK(wake_tac_create("/tmp/tac_test_bad.dat", &bad) == NULL);
    bad.capacity = 256;
    bad.occ_slots = 128;          /* occ_slots < capacity */
    CHECK(wake_tac_create("/tmp/tac_test_bad.dat", &bad) == NULL);
    bad.occ_slots = 256;
    bad.decay_corr_fp16 = 70000;  /* >= 1.0 in 0.16 fixed point */
    CHECK(wake_tac_create("/tmp/tac_test_bad.dat", &bad) == NULL);
    bad.decay_corr_fp16 = 0;
    bad.per_entity_cap = 64;      /* > WAKE_TAC_PER_ENTITY_CAP_MAX */
    CHECK(wake_tac_create("/tmp/tac_test_bad.dat", &bad) == NULL);

    wake_tac_t *t = mk("life", 8, 2, 20000);
    CHECK(t);
    size_t l;
    const uint8_t *e = E("L|e", &l);
    wake_tac_reinforce(t, e, l, wake_tac_pack(1071, 0), wake_tac_pack(1041, 0),
                       ETA_STRONG, 1, 0);
    wake_tac_close(t);

    wake_tac_t *r = wake_tac_open("/tmp/tac_test_life.dat");
    CHECK(r);
    CHECK(edges_of(r, "L|e") == 1);
    wake_tac_reset(r);
    wake_tac_stats_t st;
    wake_tac_stats(r, &st);
    CHECK(st.occupied == 0);
    CHECK(edges_of(r, "L|e") == 0);
    wake_tac_close(r);
    return 0;
}

/* label packing round-trips + is deterministic + distinct from ATT&CK ids. */
static int test_pack_label(void)
{
    uint32_t a = wake_tac_pack_label("suricata:et-scan", 16);
    uint32_t b = wake_tac_pack_label("suricata:et-scan", 16);
    CHECK(a == b);
    CHECK(WAKE_TAC_TECH_FLAGS(a) & WAKE_TAC_TECH_HASHED);
    uint32_t t1071 = wake_tac_pack(1071, 0);
    CHECK(!(WAKE_TAC_TECH_FLAGS(t1071) & WAKE_TAC_TECH_HASHED));
    CHECK(a != t1071);
    return 0;
}

/* -------------------------------------------------------------------------- */

int main(void)
{
    struct {
        const char *name;
        int (*fn)(void);
    } cases[] = {
        {"reinforce_and_decay", test_reinforce_and_decay},
        {"edge_local_writes", test_edge_local_writes},
        {"snapshot_no_verdict", test_snapshot_no_verdict},
        {"epoch_relative_clock", test_epoch_relative_clock},
        {"mass_is_force_not_semantics", test_mass_is_force_not_semantics},
        {"masking_does_not_lower_mass", test_masking_does_not_lower_mass},
        {"weak_weak_decays_faster", test_weak_weak_decays_faster},
        {"outlier_quarantine", test_outlier_quarantine},
        {"occ_pressure_cap_holds", test_occ_pressure_cap_holds},
        {"cap_evict_table_full", test_cap_evict_table_full_keeps_victim},
        {"eviction_dos_cap", test_eviction_dos_cap},
        {"replace_if_stronger", test_replace_if_stronger},
        {"per_source_budget_refusal", test_per_source_budget_refusal},
        {"shared_other_bucket_saturates", test_shared_other_bucket_saturates},
        {"occupancy_benign", test_occupancy_benign},
        {"gate_c_sim", test_gate_c_sim},
        {"lifecycle", test_lifecycle},
        {"pack_label", test_pack_label},
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
    printf("test_tac: %d/%d passed\n", passed, n);
    return g_fail ? 1 : 0;
}
