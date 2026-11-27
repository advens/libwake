/*
 * fuzz_prevmsg.c - libFuzzer: untrusted prevalence batch decode.
 *
 * A compromised peer can send any payload. decode() must fail closed and
 * never read past len. The same input is also read as rows: whatever
 * encode() accepts must decode to the same rows under the same origin.
 *
 * Copyright (c) 2026 Advens. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "wake_prevmsg.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static wake_node_key_t key;
    static int have_key;
    wake_prevmsg_t m;
    wake_prevmsg_row_t rows[WAKE_PREVMSG_MAX_ROWS];
    uint8_t buf[WAKE_PREVMSG_MAX_LEN];
    size_t n_rows, i, len;
    wake_prevmsg_status_t st;

    /* Exact length: the decoder gets no slack past the input. */
    st = wake_prevmsg_decode(&m, data, size);
    (void)wake_prevmsg_status_name(st);
    if (wake_prevmsg_probe(data, size) == false && st == WAKE_PREVMSG_OK) {
        abort();
    }

    if (!have_key) {
        uint8_t seed[WAKE_ED25519_SEED_LEN];
        memset(seed, 0x5a, sizeof(seed));
        wake_ed25519_keygen_from_seed(&key, seed);
        have_key = 1;
    }
    if (size < 1) {
        return 0;
    }
    n_rows = (size_t)(data[0] % (WAKE_PREVMSG_MAX_ROWS + 2));
    memset(rows, 0, sizeof(rows));
    for (i = 0; i < n_rows && i < WAKE_PREVMSG_MAX_ROWS; i++) {
        const uint8_t *p = data + 1 + i * WAKE_PREVMSG_ROW_LEN;
        if (1 + (i + 1) * WAKE_PREVMSG_ROW_LEN > size) {
            break;
        }
        memcpy(&rows[i].hash, p, 8);
        memcpy(&rows[i].count, p + 8, 4);
        memcpy(&rows[i].sources, p + 12, 2);
    }
    len = wake_prevmsg_encode(buf, sizeof(buf), 1, 2, 3, rows, n_rows, &key);
    if (len == 0) {
        return 0;
    }
    if (len != WAKE_PREVMSG_LEN(n_rows) || wake_prevmsg_decode(&m, buf, len) != WAKE_PREVMSG_OK) {
        abort();
    }
    if (m.n_rows != n_rows || memcmp(m.origin, key.public_key, WAKE_ED25519_PK_LEN) != 0) {
        abort();
    }
    for (i = 0; i < n_rows; i++) {
        if (m.rows[i].hash != rows[i].hash || m.rows[i].count != rows[i].count ||
            m.rows[i].sources != rows[i].sources) {
            abort();
        }
    }
    return 0;
}
