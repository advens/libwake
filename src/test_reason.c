/* test_reason.c: reason words live in the existing 24-byte pad.
 * Same kind replaces slot 0. A new kind shifts the older two down.
 * A new claim zeros a recycled slot. read_entry copies the three words.
 */
#include "wake_pheromone.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int g_fail;

#define CHECK(cond)                                                          \
    do {                                                                     \
        if (!(cond)) {                                                       \
            printf("  FAIL %s:%d  %s\n", __func__, __LINE__, #cond);         \
            g_fail = 1;                                                      \
            return 1;                                                        \
        }                                                                    \
    } while (0)

static wake_entity_t ipv4(uint32_t nbo)
{
    wake_entity_t e;
    wake_entity_init_ipv4(&e, WAKE_EC_WHO, nbo);
    return e;
}

static int find_slot(wake_pheromone_t *pt, const wake_entity_t *e, wake_pheromone_entry_t *out)
{
    uint32_t i;
    for (i = 0; i < pt->header->capacity; i++) {
        if (wake_pheromone_read_entry(pt, i, out) && wake_entity_eq(&out->entity, e))
            return 1;
    }
    return 0;
}

static int test_pack_format(void)
{
    char buf[64];
    uint64_t w = wake_reason_pack(WAKE_REASON_SCAN, 0, 60, 0);
    CHECK((w & 0xffu) == WAKE_REASON_SCAN);
    CHECK(((w >> 16) & 0xffffu) == 60u);
    CHECK(wake_reason_format(w, buf, sizeof(buf)) > 0);
    CHECK(strcmp(buf, "scan 6.0x baseline") == 0);
    w = wake_reason_pack(WAKE_REASON_SIGMA, 0, 0, 1110);
    CHECK(wake_reason_format(w, buf, sizeof(buf)) > 0);
    CHECK(strcmp(buf, "sigma T1110") == 0);
    w = wake_reason_pack(WAKE_REASON_CLASSIFY, WAKE_CLASS_GEO_TRAVEL, 0, 0);
    CHECK(wake_reason_format(w, buf, sizeof(buf)) > 0);
    CHECK(strcmp(buf, "geo travel") == 0);
    CHECK(wake_reason_format(0, buf, sizeof(buf)) == -1);
    CHECK(wake_reason_format(wake_reason_pack(WAKE_REASON_SCAN, 0, 1, 0), buf, 4) == -1);
    return 0;
}

static int test_shift_and_replace(void)
{
    wake_pheromone_config_t cfg;
    wake_pheromone_t *pt;
    wake_entity_t e = ipv4(0x0100000a);
    wake_pheromone_entry_t snap;
    char path[] = "/tmp/wake-reason-test.pht";
    uint64_t scan, brute, sigma, scan2;

    memset(&cfg, 0, sizeof(cfg));
    cfg.capacity = 16;
    unlink(path);
    pt = wake_pheromone_create(path, &cfg);
    CHECK(pt != NULL);
    CHECK(wake_pheromone_deposit(pt, &e, WAKE_ACTION_AUTH, WAKE_OUTCOME_FAILURE, 1, 100, 0) > 0);

    scan = wake_reason_pack(WAKE_REASON_SCAN, 0, 10, 0);
    brute = wake_reason_pack(WAKE_REASON_BRUTE, 0, 20, 0);
    sigma = wake_reason_pack(WAKE_REASON_SIGMA, 0, 0, 1110);
    wake_pheromone_note_reason(pt, &e, scan);
    wake_pheromone_note_reason(pt, &e, brute);
    wake_pheromone_note_reason(pt, &e, sigma);
    CHECK(find_slot(pt, &e, &snap));
    CHECK(atomic_load(&snap.reasons[0]) == sigma);
    CHECK(atomic_load(&snap.reasons[1]) == brute);
    CHECK(atomic_load(&snap.reasons[2]) == scan);

    scan2 = wake_reason_pack(WAKE_REASON_SCAN, 0, 80, 0);
    wake_pheromone_note_reason(pt, &e, scan2);
    CHECK(find_slot(pt, &e, &snap));
    /* Slot 0 was SIGMA, not SCAN, so SCAN shifts. The previous SCAN was
     * in slot 2 and falls off. Slot 0 is the new SCAN. */
    CHECK(atomic_load(&snap.reasons[0]) == scan2);
    CHECK(atomic_load(&snap.reasons[1]) == sigma);
    CHECK(atomic_load(&snap.reasons[2]) == brute);

    scan = wake_reason_pack(WAKE_REASON_SCAN, 0, 90, 0);
    wake_pheromone_note_reason(pt, &e, scan);
    CHECK(find_slot(pt, &e, &snap));
    CHECK(atomic_load(&snap.reasons[0]) == scan);
    CHECK(atomic_load(&snap.reasons[1]) == sigma);

    wake_pheromone_close(pt);
    unlink(path);
    return 0;
}

static int test_new_claim_zeros(void)
{
    wake_pheromone_config_t cfg;
    wake_pheromone_t *pt;
    wake_entity_t e = ipv4(0x0200000a);
    wake_pheromone_entry_t snap;
    char path[] = "/tmp/wake-reason-reclaim.pht";

    memset(&cfg, 0, sizeof(cfg));
    cfg.capacity = 16;
    unlink(path);
    pt = wake_pheromone_create(path, &cfg);
    CHECK(pt != NULL);
    CHECK(wake_pheromone_deposit(pt, &e, WAKE_ACTION_NETWORK, WAKE_OUTCOME_UNKNOWN, 1, 50, 0) > 0);
    wake_pheromone_note_reason(pt, &e, wake_reason_pack(WAKE_REASON_CTI, 0, 80, 0));
    CHECK(wake_pheromone_remove(pt, &e));
    CHECK(wake_pheromone_deposit(pt, &e, WAKE_ACTION_NETWORK, WAKE_OUTCOME_UNKNOWN, 1, 50, 0) > 0);
    CHECK(find_slot(pt, &e, &snap));
    CHECK(atomic_load(&snap.reasons[0]) == 0);
    CHECK(atomic_load(&snap.reasons[1]) == 0);
    CHECK(atomic_load(&snap.reasons[2]) == 0);
    wake_pheromone_close(pt);
    unlink(path);
    return 0;
}

static int test_note_without_slot(void)
{
    wake_pheromone_config_t cfg;
    wake_pheromone_t *pt;
    wake_entity_t e = ipv4(0x0300000a);
    wake_pheromone_entry_t snap;
    char path[] = "/tmp/wake-reason-empty.pht";
    uint32_t i;
    int live = 0;

    memset(&cfg, 0, sizeof(cfg));
    cfg.capacity = 16;
    unlink(path);
    pt = wake_pheromone_create(path, &cfg);
    CHECK(pt != NULL);
    wake_pheromone_note_reason(pt, &e, wake_reason_pack(WAKE_REASON_IDS, 0, 3, 0));
    for (i = 0; i < pt->header->capacity; i++) {
        if (wake_pheromone_read_entry(pt, i, &snap))
            live++;
    }
    CHECK(live == 0);
    wake_pheromone_close(pt);
    unlink(path);
    return 0;
}

int main(void)
{
    int rc = 0;
    rc |= test_pack_format();
    rc |= test_shift_and_replace();
    rc |= test_new_claim_zeros();
    rc |= test_note_without_slot();
    if (rc == 0 && !g_fail)
        printf("reason: ok\n");
    return rc || g_fail;
}
