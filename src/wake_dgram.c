/*
 * wake_dgram.c: datagram codec for the SWIM and PlumTree protocols
 *
 * Bounded codec; see wake_dgram.h. The decoder is the untrusted-input surface:
 * every field read is length-checked against buf[len] before it happens.
 *
 * Copyright (c) 2026 Advens. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "wake_dgram.h"

#include <string.h>

/* ---- little-endian scalar helpers (host-independent) -------------------- */
static inline uint16_t rd16(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}
static inline uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static inline void wr16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v & 0xff);
    p[1] = (uint8_t)((v >> 8) & 0xff);
}
static inline void wr32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v & 0xff);
    p[1] = (uint8_t)((v >> 8) & 0xff);
    p[2] = (uint8_t)((v >> 16) & 0xff);
    p[3] = (uint8_t)((v >> 24) & 0xff);
}

/* one SWIM update: 48 bytes, little-endian, same field order as wake_swim_update_t. */
static void dec_update(const uint8_t *p, wake_swim_update_t *u) {
    memset(u, 0, sizeof(*u));
    memcpy(u->node_id, p, WAKE_DGRAM_NODE_ID_LEN);
    u->addr = rd32(p + 32);
    u->port = rd16(p + 36);
    u->state = p[38];
    /* p[39] pad */
    u->incarnation = rd32(p + 40);
    u->piggyback_count = rd16(p + 44);
    /* p[46..47] pad */
}
static void enc_update(uint8_t *p, const wake_swim_update_t *u) {
    memcpy(p, u->node_id, WAKE_DGRAM_NODE_ID_LEN);
    wr32(p + 32, u->addr);
    wr16(p + 36, u->port);
    p[38] = u->state;
    p[39] = 0;
    wr32(p + 40, u->incarnation);
    wr16(p + 44, u->piggyback_count);
    wr16(p + 46, 0);
}

/* [count:1][update * count]; a missing count byte means zero updates.
 * Rejects an over-long or truncated update list. */
static int dec_updates(const uint8_t *buf, size_t len, size_t off, wake_dgram_t *out) {
    uint8_t count, i;
    if (off >= len) {
        out->n_updates = 0;
        return 0;
    }
    count = buf[off++];
    if (count > WAKE_DGRAM_MAX_UPDATES) return -1;
    if (off + (size_t)count * WAKE_DGRAM_SWIM_UPDATE_SIZE > len) return -1;
    for (i = 0; i < count; i++) {
        dec_update(buf + off, &out->updates[i]);
        off += WAKE_DGRAM_SWIM_UPDATE_SIZE;
    }
    out->n_updates = count;
    return 0;
}

int wake_dgram_decode(const uint8_t *buf, size_t len, wake_dgram_t *out) {
    size_t off;
    if (buf == NULL || out == NULL) return -1;
    if (len < WAKE_DGRAM_HDR_SIZE) return -1;
    if (buf[0] != 'W' || buf[1] != 'D') return -1;
    if (buf[2] != WAKE_DGRAM_VERSION) return -1;

    memset(out, 0, sizeof(*out));
    out->msg_type = buf[3];
    memcpy(out->sender_id, buf + 4, WAKE_DGRAM_NODE_ID_LEN);
    off = WAKE_DGRAM_HDR_SIZE;

    switch (out->msg_type) {
        case WAKE_DGRAM_SWIM_PING:
        case WAKE_DGRAM_SWIM_ACK:
            return dec_updates(buf, len, off, out);

        case WAKE_DGRAM_SWIM_PING_REQ:
            if (len < off + WAKE_DGRAM_NODE_ID_LEN) return -1;
            memcpy(out->target_id, buf + off, WAKE_DGRAM_NODE_ID_LEN);
            off += WAKE_DGRAM_NODE_ID_LEN;
            return dec_updates(buf, len, off, out);

        case WAKE_DGRAM_PT_GOSSIP: {
            uint16_t plen;
            if (len < off + WAKE_DGRAM_MSG_ID_LEN + 2) return -1;
            memcpy(out->msg_id.bytes, buf + off, WAKE_DGRAM_MSG_ID_LEN);
            off += WAKE_DGRAM_MSG_ID_LEN;
            plen = rd16(buf + off);
            off += 2;
            if (plen > WAKE_DGRAM_MAX_PAYLOAD) return -1;
            if (off + (size_t)plen > len) return -1;
            out->payload = buf + off;
            out->payload_len = plen;
            return 0;
        }

        case WAKE_DGRAM_PT_IHAVE:
        case WAKE_DGRAM_PT_GRAFT:
            if (len < off + WAKE_DGRAM_MSG_ID_LEN) return -1;
            memcpy(out->msg_id.bytes, buf + off, WAKE_DGRAM_MSG_ID_LEN);
            return 0;

        case WAKE_DGRAM_PT_PRUNE:
            return 0;

        default:
            return -1;
    }
}

/* ---- encoders ----------------------------------------------------------- */

static size_t enc_header(uint8_t *buf, size_t cap, wake_dgram_type_t type, const uint8_t sender[WAKE_DGRAM_NODE_ID_LEN]) {
    if (cap < WAKE_DGRAM_HDR_SIZE) return 0;
    buf[0] = 'W';
    buf[1] = 'D';
    buf[2] = WAKE_DGRAM_VERSION;
    buf[3] = (uint8_t)type;
    memcpy(buf + 4, sender, WAKE_DGRAM_NODE_ID_LEN);
    return WAKE_DGRAM_HDR_SIZE;
}

size_t wake_dgram_encode_swim(uint8_t *buf, size_t cap, wake_dgram_type_t type, const uint8_t sender[WAKE_DGRAM_NODE_ID_LEN],
                            const uint8_t *target_id, const wake_swim_update_t *updates, uint8_t n_updates) {
    size_t off;
    uint8_t i;
    if (n_updates > WAKE_DGRAM_MAX_UPDATES) n_updates = WAKE_DGRAM_MAX_UPDATES;
    off = enc_header(buf, cap, type, sender);
    if (off == 0) return 0;
    if (type == WAKE_DGRAM_SWIM_PING_REQ) {
        if (target_id == NULL || cap < off + WAKE_DGRAM_NODE_ID_LEN) return 0;
        memcpy(buf + off, target_id, WAKE_DGRAM_NODE_ID_LEN);
        off += WAKE_DGRAM_NODE_ID_LEN;
    }
    if (cap < off + 1 + (size_t)n_updates * WAKE_DGRAM_SWIM_UPDATE_SIZE) return 0;
    buf[off++] = n_updates;
    for (i = 0; i < n_updates; i++) {
        enc_update(buf + off, &updates[i]);
        off += WAKE_DGRAM_SWIM_UPDATE_SIZE;
    }
    return off;
}

size_t wake_dgram_encode_pt_gossip(uint8_t *buf, size_t cap, const uint8_t sender[WAKE_DGRAM_NODE_ID_LEN],
                                 const wake_plumtree_msg_id_t *msg_id, const void *payload, uint16_t payload_len) {
    size_t off;
    if (payload_len > WAKE_DGRAM_MAX_PAYLOAD) return 0;
    off = enc_header(buf, cap, WAKE_DGRAM_PT_GOSSIP, sender);
    if (off == 0) return 0;
    if (cap < off + WAKE_DGRAM_MSG_ID_LEN + 2 + (size_t)payload_len) return 0;
    memcpy(buf + off, msg_id->bytes, WAKE_DGRAM_MSG_ID_LEN);
    off += WAKE_DGRAM_MSG_ID_LEN;
    wr16(buf + off, payload_len);
    off += 2;
    if (payload_len > 0) memcpy(buf + off, payload, payload_len);
    off += payload_len;
    return off;
}

size_t wake_dgram_encode_pt_ctrl(uint8_t *buf, size_t cap, wake_dgram_type_t type,
                               const uint8_t sender[WAKE_DGRAM_NODE_ID_LEN], const wake_plumtree_msg_id_t *msg_id) {
    size_t off = enc_header(buf, cap, type, sender);
    if (off == 0) return 0;
    if (type == WAKE_DGRAM_PT_PRUNE) return off;
    if (cap < off + WAKE_DGRAM_MSG_ID_LEN) return 0;
    memcpy(buf + off, msg_id->bytes, WAKE_DGRAM_MSG_ID_LEN);
    off += WAKE_DGRAM_MSG_ID_LEN;
    return off;
}
