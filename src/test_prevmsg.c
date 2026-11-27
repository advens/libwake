/*
 * test_prevmsg.c: wake_prevmsg encode / decode tests
 *
 * Round-trips one and ten rows, pins the header bytes and lengths, flips
 * every bit of a signed batch, and checks that each class of malformed or
 * forged input is refused. No network, no clock.
 *
 * Copyright (c) 2026 Advens. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "wake_prevmsg.h"

#include <stdio.h>
#include <string.h>

static int g_fail;

#define CHECK(cond)                                                             \
    do {                                                                        \
        if (!(cond)) {                                                          \
            printf("  FAIL %s:%d  %s\n", __func__, __LINE__, #cond);            \
            g_fail = 1;                                                         \
            return 1;                                                           \
        }                                                                       \
    } while (0)

static void mk_key(wake_node_key_t *key, uint8_t fill)
{
    uint8_t seed[WAKE_ED25519_SEED_LEN];
    memset(seed, fill, sizeof(seed));
    wake_ed25519_keygen_from_seed(key, seed);
}

static void mk_rows(wake_prevmsg_row_t *rows, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) {
        rows[i].hash = UINT64_C(0x0102030405060708) * (uint64_t)(i + 1);
        rows[i].count = 1000u + (uint32_t)i;
        rows[i].sources = (uint16_t)(1 + i);
    }
}

static int test_round_trip(void)
{
    wake_node_key_t key;
    wake_prevmsg_row_t rows[WAKE_PREVMSG_MAX_ROWS];
    uint8_t buf[WAKE_PREVMSG_MAX_LEN];
    wake_prevmsg_t m;
    size_t n, i;

    mk_key(&key, 0x11);
    mk_rows(rows, WAKE_PREVMSG_MAX_ROWS);

    n = wake_prevmsg_encode(buf, sizeof(buf), 7, 0xa1b2c3d4u, 1795000000u, rows, 1, &key);
    CHECK(n == 126);
    CHECK(wake_prevmsg_decode(&m, buf, n) == WAKE_PREVMSG_OK);
    CHECK(m.n_rows == 1 && m.rows[0].hash == rows[0].hash);

    n = wake_prevmsg_encode(buf, sizeof(buf), 7, 0xa1b2c3d4u, 1795000000u, rows, WAKE_PREVMSG_MAX_ROWS, &key);
    CHECK(n == 252 && n == WAKE_PREVMSG_MAX_LEN);
    CHECK(buf[0] == 'W' && buf[1] == 'P' && buf[2] == WAKE_PREVMSG_VERSION && buf[3] == WAKE_PREVMSG_MAX_ROWS);
    CHECK(buf[4] == 7 && buf[5] == 0 && buf[6] == 0 && buf[7] == 0);
    CHECK(buf[8] == 0xd4 && buf[11] == 0xa1);
    CHECK(memcmp(buf + 16, key.public_key, WAKE_ED25519_PK_LEN) == 0);
    CHECK(buf[48] == 0x08 && buf[55] == 0x01); /* first hash, little-endian */
    CHECK(wake_prevmsg_probe(buf, n));
    CHECK(wake_prevmsg_decode(&m, buf, n) == WAKE_PREVMSG_OK);
    CHECK(m.tenant_id == 7 && m.key_id == 0xa1b2c3d4u && m.window_start == 1795000000u);
    CHECK(memcmp(m.origin, key.public_key, WAKE_ED25519_PK_LEN) == 0);
    CHECK(m.n_rows == WAKE_PREVMSG_MAX_ROWS);
    for (i = 0; i < WAKE_PREVMSG_MAX_ROWS; i++) {
        CHECK(m.rows[i].hash == rows[i].hash);
        CHECK(m.rows[i].count == rows[i].count);
        CHECK(m.rows[i].sources == rows[i].sources);
    }
    return 0;
}

/* Every single-bit change of a signed batch is refused. */
static int test_every_bit_flip_fails(void)
{
    wake_node_key_t key;
    wake_prevmsg_row_t rows[WAKE_PREVMSG_MAX_ROWS];
    uint8_t buf[WAKE_PREVMSG_MAX_LEN];
    wake_prevmsg_t m;
    size_t n, byte;
    int bit;

    mk_key(&key, 0x22);
    mk_rows(rows, WAKE_PREVMSG_MAX_ROWS);
    n = wake_prevmsg_encode(buf, sizeof(buf), 1, 2, 3, rows, WAKE_PREVMSG_MAX_ROWS, &key);
    CHECK(n == WAKE_PREVMSG_MAX_LEN);
    for (byte = 0; byte < n; byte++) {
        for (bit = 0; bit < 8; bit++) {
            buf[byte] ^= (uint8_t)(1u << bit);
            CHECK(wake_prevmsg_decode(&m, buf, n) != WAKE_PREVMSG_OK);
            CHECK(m.n_rows == 0 && m.tenant_id == 0);
            buf[byte] ^= (uint8_t)(1u << bit);
        }
    }
    CHECK(wake_prevmsg_decode(&m, buf, n) == WAKE_PREVMSG_OK);
    return 0;
}

static int test_encode_refuses(void)
{
    wake_node_key_t key;
    wake_prevmsg_row_t rows[WAKE_PREVMSG_MAX_ROWS + 1];
    uint8_t buf[WAKE_PREVMSG_MAX_LEN + 16];
    uint8_t untouched[sizeof(buf)];

    mk_key(&key, 0x33);
    mk_rows(rows, WAKE_PREVMSG_MAX_ROWS + 1);
    memset(buf, 0xee, sizeof(buf));
    memcpy(untouched, buf, sizeof(buf));

    CHECK(wake_prevmsg_encode(buf, sizeof(buf), 1, 2, 3, rows, 0, &key) == 0);
    CHECK(wake_prevmsg_encode(buf, sizeof(buf), 1, 2, 3, rows, WAKE_PREVMSG_MAX_ROWS + 1, &key) == 0);
    CHECK(wake_prevmsg_encode(buf, WAKE_PREVMSG_LEN(2) - 1, 1, 2, 3, rows, 2, &key) == 0);
    CHECK(wake_prevmsg_encode(NULL, sizeof(buf), 1, 2, 3, rows, 1, &key) == 0);
    CHECK(wake_prevmsg_encode(buf, sizeof(buf), 1, 2, 3, NULL, 1, &key) == 0);
    CHECK(wake_prevmsg_encode(buf, sizeof(buf), 1, 2, 3, rows, 1, NULL) == 0);

    rows[1].count = 0;
    CHECK(wake_prevmsg_encode(buf, sizeof(buf), 1, 2, 3, rows, 3, &key) == 0);
    mk_rows(rows, 3);
    rows[2].count = 5;
    rows[2].sources = 6;
    CHECK(wake_prevmsg_encode(buf, sizeof(buf), 1, 2, 3, rows, 3, &key) == 0);
    mk_rows(rows, 3);
    rows[2].hash = rows[0].hash;
    CHECK(wake_prevmsg_encode(buf, sizeof(buf), 1, 2, 3, rows, 3, &key) == 0);
    CHECK(memcmp(buf, untouched, sizeof(buf)) == 0);

    mk_rows(rows, 2);
    CHECK(wake_prevmsg_encode(buf, WAKE_PREVMSG_LEN(2), 1, 2, 3, rows, 2, &key) == WAKE_PREVMSG_LEN(2));
    return 0;
}

/* Rewrite the header and re-sign, so only the field under test is wrong. */
static size_t resign(uint8_t *buf, size_t len, const wake_node_key_t *key)
{
    size_t signed_len = len - WAKE_ED25519_SIG_LEN;
    wake_ed25519_sign(buf + signed_len, buf, signed_len, key);
    return len;
}

static int test_decode_refuses(void)
{
    wake_node_key_t key, other;
    wake_prevmsg_row_t rows[WAKE_PREVMSG_MAX_ROWS];
    uint8_t buf[WAKE_PREVMSG_MAX_LEN + 16];
    uint8_t good[sizeof(buf)];
    wake_prevmsg_t m;
    size_t n;

    mk_key(&key, 0x44);
    mk_key(&other, 0x55);
    mk_rows(rows, 4);
    n = wake_prevmsg_encode(good, sizeof(good), 1, 2, 3, rows, 4, &key);
    CHECK(n == WAKE_PREVMSG_LEN(4));

    CHECK(wake_prevmsg_decode(&m, good, n - 1) == WAKE_PREVMSG_ELENGTH);
    CHECK(wake_prevmsg_decode(&m, good, n + 1) == WAKE_PREVMSG_ELENGTH);
    CHECK(wake_prevmsg_decode(&m, good, 0) == WAKE_PREVMSG_ELENGTH);
    CHECK(wake_prevmsg_decode(&m, NULL, n) == WAKE_PREVMSG_ELENGTH);
    CHECK(wake_prevmsg_decode(NULL, good, n) == WAKE_PREVMSG_ELENGTH);

    memcpy(buf, good, n);
    buf[1] = 'Q';
    CHECK(wake_prevmsg_decode(&m, buf, resign(buf, n, &key)) == WAKE_PREVMSG_EMAGIC);

    memcpy(buf, good, n);
    buf[2] = WAKE_PREVMSG_VERSION + 1;
    CHECK(wake_prevmsg_decode(&m, buf, resign(buf, n, &key)) == WAKE_PREVMSG_EVERSION);

    memcpy(buf, good, n);
    buf[3] = 0;
    CHECK(wake_prevmsg_decode(&m, buf, resign(buf, n, &key)) == WAKE_PREVMSG_EROWS);

    /* Eleven rows would be 266 bytes. Claim them in a full-size buffer. */
    n = wake_prevmsg_encode(good, sizeof(good), 1, 2, 3, rows, 4, &key);
    memset(buf, 0, sizeof(buf));
    memcpy(buf, good, WAKE_PREVMSG_HDR_LEN);
    buf[3] = WAKE_PREVMSG_MAX_ROWS + 1;
    CHECK(wake_prevmsg_decode(&m, buf, WAKE_PREVMSG_MAX_LEN) == WAKE_PREVMSG_EROWS);

    /* A row count that does not match the length. */
    memcpy(buf, good, n);
    buf[3] = 3;
    CHECK(wake_prevmsg_decode(&m, buf, resign(buf, n, &key)) == WAKE_PREVMSG_ELENGTH);

    /* A signed batch with a zero count, sources above count, a repeated hash. */
    memcpy(buf, good, n);
    memset(buf + WAKE_PREVMSG_HDR_LEN + 8, 0, 4);
    CHECK(wake_prevmsg_decode(&m, buf, resign(buf, n, &key)) == WAKE_PREVMSG_EROW);
    memcpy(buf, good, n);
    buf[WAKE_PREVMSG_HDR_LEN + 12] = 0xff;
    buf[WAKE_PREVMSG_HDR_LEN + 13] = 0xff;
    buf[WAKE_PREVMSG_HDR_LEN + 8] = 1;
    buf[WAKE_PREVMSG_HDR_LEN + 9] = 0;
    buf[WAKE_PREVMSG_HDR_LEN + 10] = 0;
    buf[WAKE_PREVMSG_HDR_LEN + 11] = 0;
    CHECK(wake_prevmsg_decode(&m, buf, resign(buf, n, &key)) == WAKE_PREVMSG_EROW);
    memcpy(buf, good, n);
    memcpy(buf + WAKE_PREVMSG_HDR_LEN + WAKE_PREVMSG_ROW_LEN, buf + WAKE_PREVMSG_HDR_LEN, 8);
    CHECK(wake_prevmsg_decode(&m, buf, resign(buf, n, &key)) == WAKE_PREVMSG_EROW);

    /* Another node's key put in place of the origin: the signature fails. */
    memcpy(buf, good, n);
    memcpy(buf + 16, other.public_key, WAKE_ED25519_PK_LEN);
    CHECK(wake_prevmsg_decode(&m, buf, n) == WAKE_PREVMSG_ESIG);
    /* Signed by another node but claiming the first node as origin. */
    memcpy(buf, good, n);
    CHECK(wake_prevmsg_decode(&m, buf, resign(buf, n, &other)) == WAKE_PREVMSG_ESIG);

    CHECK(wake_prevmsg_decode(&m, good, n) == WAKE_PREVMSG_OK);
    return 0;
}

static int test_probe(void)
{
    wake_node_key_t key;
    wake_prevmsg_row_t rows[3];
    uint8_t buf[256];
    size_t n;

    mk_key(&key, 0x66);
    mk_rows(rows, 3);
    n = wake_prevmsg_encode(buf, sizeof(buf), 1, 2, 3, rows, 3, &key);
    CHECK(wake_prevmsg_probe(buf, n));
    CHECK(!wake_prevmsg_probe(buf, n - 1));
    CHECK(!wake_prevmsg_probe(buf, 192)); /* the wake_signal_t size */
    CHECK(!wake_prevmsg_probe(NULL, n));
    buf[0] = 'X';
    CHECK(!wake_prevmsg_probe(buf, n));
    CHECK(strcmp(wake_prevmsg_status_name(WAKE_PREVMSG_ESIG), "signature") == 0);
    CHECK(strcmp(wake_prevmsg_status_name((wake_prevmsg_status_t)42), "unknown") == 0);
    return 0;
}

int main(void)
{
    int (*tests[])(void) = {test_round_trip, test_every_bit_flip_fails, test_encode_refuses, test_decode_refuses,
                            test_probe};
    size_t i, ran = 0;

    for (i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        if (tests[i]() == 0) {
            ran++;
        }
    }
    printf("test_prevmsg: %zu/%zu passed\n", ran, sizeof(tests) / sizeof(tests[0]));
    return g_fail ? 1 : 0;
}
