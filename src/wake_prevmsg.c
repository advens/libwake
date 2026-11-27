/*
 * wake_prevmsg.c: signed prevalence batch, encode and decode
 *
 * Every field is written byte by byte in little-endian order, so the wire
 * image does not depend on struct layout or host byte order.
 *
 * Copyright (c) 2026 Advens. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "wake_prevmsg.h"

#include <string.h>

_Static_assert(WAKE_PREVMSG_MAX_LEN <= 256, "a batch must fit one PlumTree payload (WAKE_PLUMTREE_MAX_PAYLOAD)");
_Static_assert(WAKE_PREVMSG_MAX_ROWS <= UINT8_MAX, "the row count is one byte");

static void put16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
}

static void put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static void put64(uint8_t *p, uint64_t v)
{
    put32(p, (uint32_t)v);
    put32(p + 4, (uint32_t)(v >> 32));
}

static uint16_t get16(const uint8_t *p)
{
    return (uint16_t)(p[0] | (uint16_t)(p[1] << 8));
}

static uint32_t get32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t get64(const uint8_t *p)
{
    return (uint64_t)get32(p) | ((uint64_t)get32(p + 4) << 32);
}

/* count >= 1, sources <= count, and no hash repeated among rows[0..n). */
static bool rows_ok(const wake_prevmsg_row_t *rows, size_t n)
{
    size_t i, j;
    for (i = 0; i < n; i++) {
        if (rows[i].count == 0 || (uint32_t)rows[i].sources > rows[i].count) {
            return false;
        }
        for (j = 0; j < i; j++) {
            if (rows[j].hash == rows[i].hash) {
                return false;
            }
        }
    }
    return true;
}

size_t wake_prevmsg_encode(uint8_t *buf,
                           size_t cap,
                           uint32_t tenant_id,
                           uint32_t key_id,
                           uint32_t window_start,
                           const wake_prevmsg_row_t *rows,
                           size_t n_rows,
                           const wake_node_key_t *key)
{
    size_t len, signed_len, i;
    uint8_t *p;

    if (buf == NULL || rows == NULL || key == NULL) {
        return 0;
    }
    if (n_rows == 0 || n_rows > WAKE_PREVMSG_MAX_ROWS) {
        return 0;
    }
    len = WAKE_PREVMSG_LEN(n_rows);
    if (cap < len || !rows_ok(rows, n_rows)) {
        return 0;
    }
    signed_len = len - WAKE_ED25519_SIG_LEN;

    buf[0] = 'W';
    buf[1] = 'P';
    buf[2] = WAKE_PREVMSG_VERSION;
    buf[3] = (uint8_t)n_rows;
    put32(buf + 4, tenant_id);
    put32(buf + 8, key_id);
    put32(buf + 12, window_start);
    memcpy(buf + 16, key->public_key, WAKE_ED25519_PK_LEN);
    p = buf + WAKE_PREVMSG_HDR_LEN;
    for (i = 0; i < n_rows; i++) {
        put64(p, rows[i].hash);
        put32(p + 8, rows[i].count);
        put16(p + 12, rows[i].sources);
        p += WAKE_PREVMSG_ROW_LEN;
    }
    wake_ed25519_sign(buf + signed_len, buf, signed_len, key);
    return len;
}

wake_prevmsg_status_t wake_prevmsg_decode(wake_prevmsg_t *out, const void *buf, size_t len)
{
    const uint8_t *b = (const uint8_t *)buf;
    wake_prevmsg_t m;
    size_t n, i, signed_len;
    const uint8_t *p;

    if (out != NULL) {
        memset(out, 0, sizeof(*out));
    }
    if (out == NULL || buf == NULL || len < WAKE_PREVMSG_MIN_LEN || len > WAKE_PREVMSG_MAX_LEN) {
        return WAKE_PREVMSG_ELENGTH;
    }
    if (b[0] != 'W' || b[1] != 'P') {
        return WAKE_PREVMSG_EMAGIC;
    }
    if (b[2] != WAKE_PREVMSG_VERSION) {
        return WAKE_PREVMSG_EVERSION;
    }
    n = b[3];
    if (n == 0 || n > WAKE_PREVMSG_MAX_ROWS) {
        return WAKE_PREVMSG_EROWS;
    }
    if (len != WAKE_PREVMSG_LEN(n)) {
        return WAKE_PREVMSG_ELENGTH;
    }

    memset(&m, 0, sizeof(m));
    m.tenant_id = get32(b + 4);
    m.key_id = get32(b + 8);
    m.window_start = get32(b + 12);
    memcpy(m.origin, b + 16, WAKE_ED25519_PK_LEN);
    m.n_rows = (uint8_t)n;
    p = b + WAKE_PREVMSG_HDR_LEN;
    for (i = 0; i < n; i++) {
        m.rows[i].hash = get64(p);
        m.rows[i].count = get32(p + 8);
        m.rows[i].sources = get16(p + 12);
        p += WAKE_PREVMSG_ROW_LEN;
    }
    if (!rows_ok(m.rows, n)) {
        return WAKE_PREVMSG_EROW;
    }

    signed_len = len - WAKE_ED25519_SIG_LEN;
    if (wake_ed25519_verify(b + signed_len, b, signed_len, m.origin) != 0) {
        return WAKE_PREVMSG_ESIG;
    }
    *out = m;
    return WAKE_PREVMSG_OK;
}

bool wake_prevmsg_probe(const void *buf, size_t len)
{
    const uint8_t *b = (const uint8_t *)buf;
    size_t n;

    if (buf == NULL || len < WAKE_PREVMSG_MIN_LEN || len > WAKE_PREVMSG_MAX_LEN) {
        return false;
    }
    if (b[0] != 'W' || b[1] != 'P' || b[2] != WAKE_PREVMSG_VERSION) {
        return false;
    }
    n = b[3];
    return n >= 1 && n <= WAKE_PREVMSG_MAX_ROWS && len == WAKE_PREVMSG_LEN(n);
}

const char *wake_prevmsg_status_name(wake_prevmsg_status_t status)
{
    switch (status) {
        case WAKE_PREVMSG_OK:
            return "ok";
        case WAKE_PREVMSG_ELENGTH:
            return "length";
        case WAKE_PREVMSG_EMAGIC:
            return "magic";
        case WAKE_PREVMSG_EVERSION:
            return "version";
        case WAKE_PREVMSG_EROWS:
            return "rows";
        case WAKE_PREVMSG_EROW:
            return "row";
        case WAKE_PREVMSG_ESIG:
            return "signature";
    }
    return "unknown";
}
