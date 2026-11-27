/*
 * wake_prevmsg.h: signed prevalence batch
 *
 * A prevalence batch tells the other nodes how often its origin saw a set
 * of values in one counting window. A value travels as a 64-bit keyed hash,
 * never in clear; the key is shared by the nodes of one tenant and named
 * by key_id. The batch fits one PlumTree payload and is signed with the
 * origin's Ed25519 key. The origin's public key is inside the signed bytes,
 * so a relay cannot replay a batch under another node id, and a relayed
 * batch verifies without the hop that forwarded it.
 *
 * Wire format, all integers little-endian:
 *   [0..1]    magic "WP"
 *   [2]       version (WAKE_PREVMSG_VERSION)
 *   [3]       row count, 1..WAKE_PREVMSG_MAX_ROWS
 *   [4..7]    tenant_id
 *   [8..11]   key_id: which tenant key hashed the rows
 *   [12..15]  window_start, epoch seconds
 *   [16..47]  origin: Ed25519 public key of the signer
 *   [48..]    rows, 14 bytes each: hash u64, count u32, sources u16
 *   [last 64] Ed25519 signature over every byte before it
 *
 * A batch of n rows is WAKE_PREVMSG_LEN(n) bytes: 126 for one row, 252
 * for ten. A 192-byte wake_signal_t never has that length.
 *
 * The decoder checks framing, row bounds and the signature. Tenant, key_id,
 * window, and whether the origin is a known member are the caller's checks.
 *
 * Copyright (c) 2026 Advens. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef WAKE_PREVMSG_H
#define WAKE_PREVMSG_H

#include "wake_crypto.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WAKE_PREVMSG_VERSION 1
#define WAKE_PREVMSG_MAX_ROWS 10
#define WAKE_PREVMSG_HDR_LEN 48
#define WAKE_PREVMSG_ROW_LEN 14
#define WAKE_PREVMSG_LEN(n) (WAKE_PREVMSG_HDR_LEN + WAKE_PREVMSG_ROW_LEN * (n) + WAKE_ED25519_SIG_LEN)
#define WAKE_PREVMSG_MIN_LEN WAKE_PREVMSG_LEN(1)
#define WAKE_PREVMSG_MAX_LEN WAKE_PREVMSG_LEN(WAKE_PREVMSG_MAX_ROWS)

/* One value seen by the origin in the window. */
typedef struct {
    uint64_t hash;    /* keyed hash of the value                     */
    uint32_t count;   /* events that named it, at least 1             */
    uint16_t sources; /* distinct local sources that named it, <= count */
} wake_prevmsg_row_t;

/* A decoded batch. */
typedef struct {
    uint32_t tenant_id;
    uint32_t key_id;
    uint32_t window_start;
    uint8_t origin[WAKE_ED25519_PK_LEN];
    uint8_t n_rows;
    wake_prevmsg_row_t rows[WAKE_PREVMSG_MAX_ROWS];
} wake_prevmsg_t;

typedef enum {
    WAKE_PREVMSG_OK = 0,
    WAKE_PREVMSG_ELENGTH = -1,  /* length is not WAKE_PREVMSG_LEN(n)      */
    WAKE_PREVMSG_EMAGIC = -2,   /* not "WP"                               */
    WAKE_PREVMSG_EVERSION = -3, /* unknown version                        */
    WAKE_PREVMSG_EROWS = -4,    /* row count 0 or above the maximum       */
    WAKE_PREVMSG_EROW = -5,     /* count 0, sources > count, repeated hash */
    WAKE_PREVMSG_ESIG = -6      /* signature does not verify              */
} wake_prevmsg_status_t;

/*
 * Encode and sign a batch. The origin is key's public key.
 *
 * rows must hold 1..WAKE_PREVMSG_MAX_ROWS rows, each with count >= 1,
 * sources <= count, and a hash no other row in the batch has.
 * Returns the bytes written, WAKE_PREVMSG_LEN(n_rows), or 0 when an
 * argument is NULL, a row is refused, or cap is too small. Nothing is
 * written on 0.
 */
size_t wake_prevmsg_encode(uint8_t *buf,
                           size_t cap,
                           uint32_t tenant_id,
                           uint32_t key_id,
                           uint32_t window_start,
                           const wake_prevmsg_row_t *rows,
                           size_t n_rows,
                           const wake_node_key_t *key);

/*
 * Decode and verify one batch of exactly len bytes. On WAKE_PREVMSG_OK, out
 * holds the batch; on any other status out is zeroed. The signature is
 * checked against the origin carried in the batch.
 */
wake_prevmsg_status_t wake_prevmsg_decode(wake_prevmsg_t *out, const void *buf, size_t len);

/*
 * True when buf starts like a batch of version 1 and len is a batch length.
 * No signature check: a cheap dispatch test for a payload of unknown type.
 */
bool wake_prevmsg_probe(const void *buf, size_t len);

const char *wake_prevmsg_status_name(wake_prevmsg_status_t status);

#ifdef __cplusplus
}
#endif

#endif /* WAKE_PREVMSG_H */
