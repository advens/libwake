/*
 * wake_dgram.h: datagram codec for the SWIM and PlumTree protocols
 *
 * Encodes and decodes the messages that wake_swim and wake_plumtree exchange
 * between nodes. libwake itself is transport-free: a host application that
 * uses UDP can use this codec unchanged, or supply its own framing.
 *
 * Common header (36 bytes, all fields little-endian):
 *   magic("WD":2) + version(1) + msg_type(1) + sender_id(32)
 * Message types:
 *   SWIM_PING(0) SWIM_ACK(1) SWIM_PING_REQ(2)
 *   PT_GOSSIP(3) PT_IHAVE(4) PT_GRAFT(5) PT_PRUNE(6)
 * SWIM update: 48 bytes. Largest datagram is SWIM_PING_REQ with 8 updates
 * (453 bytes). SWIM_PING with 8 updates is 421.
 *
 * The decoder parses UNTRUSTED peer input: it is fully bounded (never reads past
 * buf[len]) and is the fuzz target (fuzz_dgram.c).
 *
 * Copyright (c) 2026 Advens. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef WAKE_DGRAM_H
#define WAKE_DGRAM_H

#include <stddef.h>
#include <stdint.h>

#include "wake_plumtree.h" /* wake_plumtree_msg_id_t */
#include "wake_swim.h"     /* wake_swim_update_t */

#define WAKE_DGRAM_VERSION 1
#define WAKE_DGRAM_HDR_SIZE 36
#define WAKE_DGRAM_NODE_ID_LEN 32
#define WAKE_DGRAM_MSG_ID_LEN 16
#define WAKE_DGRAM_SWIM_UPDATE_SIZE 48
#define WAKE_DGRAM_MAX_UPDATES 8   /* protocol cap: SWIM_PING with 8 updates = 421B */
#define WAKE_DGRAM_MAX_PAYLOAD 256 /* WAKE_PLUMTREE_MAX_PAYLOAD, covers the 192B signal */
#define WAKE_DGRAM_MAX_LEN 1024  /* recv buffer; > any legal datagram */

typedef enum {
    WAKE_DGRAM_SWIM_PING = 0,
    WAKE_DGRAM_SWIM_ACK = 1,
    WAKE_DGRAM_SWIM_PING_REQ = 2,
    WAKE_DGRAM_PT_GOSSIP = 3,
    WAKE_DGRAM_PT_IHAVE = 4,
    WAKE_DGRAM_PT_GRAFT = 5,
    WAKE_DGRAM_PT_PRUNE = 6
} wake_dgram_type_t;

/* A decoded datagram.  For PT_GOSSIP, `payload` aliases the input buffer (no
 * copy); it is valid only until the buffer is reused. */
typedef struct {
    uint8_t msg_type;
    uint8_t sender_id[WAKE_DGRAM_NODE_ID_LEN];
    uint8_t target_id[WAKE_DGRAM_NODE_ID_LEN]; /* SWIM_PING_REQ only */
    wake_swim_update_t updates[WAKE_DGRAM_MAX_UPDATES];
    uint8_t n_updates;
    wake_plumtree_msg_id_t msg_id; /* PT_GOSSIP / PT_IHAVE / PT_GRAFT */
    const uint8_t *payload;        /* PT_GOSSIP payload, aliases input */
    uint16_t payload_len;
} wake_dgram_t;

/* Decode one datagram.  Returns 0 on success (out fully populated), <0 if
 * malformed.  BOUNDED: never reads past buf[len].  Safe on any input. */
int wake_dgram_decode(const uint8_t *buf, size_t len, wake_dgram_t *out);

/* Encoders return the number of bytes written, or 0 if `cap` is insufficient.
 * n_updates is clamped to WAKE_DGRAM_MAX_UPDATES.  target_id is used only for
 * SWIM_PING_REQ (pass NULL otherwise). */
size_t wake_dgram_encode_swim(uint8_t *buf, size_t cap, wake_dgram_type_t type, const uint8_t sender[WAKE_DGRAM_NODE_ID_LEN],
                            const uint8_t *target_id, const wake_swim_update_t *updates, uint8_t n_updates);
size_t wake_dgram_encode_pt_gossip(uint8_t *buf, size_t cap, const uint8_t sender[WAKE_DGRAM_NODE_ID_LEN],
                                 const wake_plumtree_msg_id_t *msg_id, const void *payload, uint16_t payload_len);
size_t wake_dgram_encode_pt_ctrl(uint8_t *buf, size_t cap, wake_dgram_type_t type,
                               const uint8_t sender[WAKE_DGRAM_NODE_ID_LEN], const wake_plumtree_msg_id_t *msg_id);

#endif /* WAKE_DGRAM_H */
