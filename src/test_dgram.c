/*
 * test_dgram.c: wake_dgram codec tests
 *
 * Round-trips every message type, pins the header bytes and size limits, and
 * checks that each class of malformed input is rejected. No network, no clock.
 *
 * Copyright (c) 2026 Advens. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "wake_dgram.h"

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

static void mk_id(uint8_t out[WAKE_DGRAM_NODE_ID_LEN], uint8_t fill) { memset(out, fill, WAKE_DGRAM_NODE_ID_LEN); }

static void mk_updates(wake_swim_update_t *u, int n) {
    int i;
    memset(u, 0, sizeof(*u) * (size_t)n);
    for (i = 0; i < n; i++) {
        memset(u[i].node_id, 0x10 + i, WAKE_DGRAM_NODE_ID_LEN);
        u[i].addr = 0xc0a80300u + (uint32_t)i;
        u[i].port = (uint16_t)(7946 + i);
        u[i].state = (uint8_t)(i % 4);
        u[i].incarnation = 100u + (uint32_t)i;
        u[i].piggyback_count = (uint16_t)i;
    }
}

static int same_update(const wake_swim_update_t *a, const wake_swim_update_t *b) {
    return memcmp(a->node_id, b->node_id, WAKE_DGRAM_NODE_ID_LEN) == 0 && a->addr == b->addr && a->port == b->port &&
           a->state == b->state && a->incarnation == b->incarnation && a->piggyback_count == b->piggyback_count;
}

static int test_ping_with_max_updates(void) {
    uint8_t sender[WAKE_DGRAM_NODE_ID_LEN], buf[WAKE_DGRAM_MAX_LEN];
    wake_swim_update_t up[WAKE_DGRAM_MAX_UPDATES];
    wake_dgram_t m;
    size_t n;
    int i;
    mk_id(sender, 0x01);
    mk_updates(up, WAKE_DGRAM_MAX_UPDATES);
    n = wake_dgram_encode_swim(buf, sizeof(buf), WAKE_DGRAM_SWIM_PING, sender, NULL, up, WAKE_DGRAM_MAX_UPDATES);
    CHECK(n == 421); /* 36 header + 1 count + 8 * 48 */
    CHECK(buf[0] == 'W' && buf[1] == 'D' && buf[2] == WAKE_DGRAM_VERSION && buf[3] == WAKE_DGRAM_SWIM_PING);
    CHECK(memcmp(buf + 4, sender, WAKE_DGRAM_NODE_ID_LEN) == 0);
    CHECK(wake_dgram_decode(buf, n, &m) == 0);
    CHECK(m.msg_type == WAKE_DGRAM_SWIM_PING);
    CHECK(memcmp(m.sender_id, sender, WAKE_DGRAM_NODE_ID_LEN) == 0);
    CHECK(m.n_updates == WAKE_DGRAM_MAX_UPDATES);
    for (i = 0; i < WAKE_DGRAM_MAX_UPDATES; i++) CHECK(same_update(&m.updates[i], &up[i]));
    return 0;
}

static int test_encoder_clamps_update_count(void) {
    uint8_t sender[WAKE_DGRAM_NODE_ID_LEN], buf[WAKE_DGRAM_MAX_LEN];
    wake_swim_update_t up[WAKE_DGRAM_MAX_UPDATES + 1];
    wake_dgram_t m;
    size_t n;
    mk_id(sender, 0x02);
    mk_updates(up, WAKE_DGRAM_MAX_UPDATES + 1);
    n = wake_dgram_encode_swim(buf, sizeof(buf), WAKE_DGRAM_SWIM_ACK, sender, NULL, up, WAKE_DGRAM_MAX_UPDATES + 1);
    CHECK(n == 421);
    CHECK(wake_dgram_decode(buf, n, &m) == 0 && m.n_updates == WAKE_DGRAM_MAX_UPDATES);
    return 0;
}

static int test_ping_req_carries_target(void) {
    uint8_t sender[WAKE_DGRAM_NODE_ID_LEN], target[WAKE_DGRAM_NODE_ID_LEN], buf[WAKE_DGRAM_MAX_LEN];
    wake_swim_update_t up[2];
    wake_dgram_t m;
    size_t n;
    mk_id(sender, 0x03);
    mk_id(target, 0x04);
    mk_updates(up, 2);
    n = wake_dgram_encode_swim(buf, sizeof(buf), WAKE_DGRAM_SWIM_PING_REQ, sender, target, up, 2);
    CHECK(n == 36 + 32 + 1 + 2 * 48);
    CHECK(wake_dgram_decode(buf, n, &m) == 0);
    CHECK(m.msg_type == WAKE_DGRAM_SWIM_PING_REQ && m.n_updates == 2);
    CHECK(memcmp(m.target_id, target, WAKE_DGRAM_NODE_ID_LEN) == 0);
    CHECK(wake_dgram_encode_swim(buf, sizeof(buf), WAKE_DGRAM_SWIM_PING_REQ, sender, NULL, up, 0) == 0);
    return 0;
}

static int test_gossip_round_trip_and_alias(void) {
    uint8_t sender[WAKE_DGRAM_NODE_ID_LEN], buf[WAKE_DGRAM_MAX_LEN], payload[192];
    wake_plumtree_msg_id_t mid;
    wake_dgram_t m;
    size_t n, i;
    mk_id(sender, 0x05);
    for (i = 0; i < sizeof(payload); i++) payload[i] = (uint8_t)(i * 7);
    memset(mid.bytes, 0xab, sizeof(mid.bytes));
    n = wake_dgram_encode_pt_gossip(buf, sizeof(buf), sender, &mid, payload, sizeof(payload));
    CHECK(n == 36 + 16 + 2 + 192);
    CHECK(wake_dgram_decode(buf, n, &m) == 0);
    CHECK(m.msg_type == WAKE_DGRAM_PT_GOSSIP && m.payload_len == 192);
    CHECK(memcmp(m.msg_id.bytes, mid.bytes, sizeof(mid.bytes)) == 0);
    CHECK(m.payload == buf + 36 + 16 + 2); /* aliases the input buffer, no copy */
    CHECK(memcmp(m.payload, payload, sizeof(payload)) == 0);
    CHECK(wake_dgram_encode_pt_gossip(buf, sizeof(buf), sender, &mid, payload, WAKE_DGRAM_MAX_PAYLOAD + 1) == 0);
    return 0;
}

static int test_plumtree_control_messages(void) {
    uint8_t sender[WAKE_DGRAM_NODE_ID_LEN], buf[WAKE_DGRAM_MAX_LEN];
    wake_plumtree_msg_id_t mid;
    wake_dgram_t m;
    size_t n;
    mk_id(sender, 0x06);
    memset(mid.bytes, 0xcd, sizeof(mid.bytes));

    n = wake_dgram_encode_pt_ctrl(buf, sizeof(buf), WAKE_DGRAM_PT_IHAVE, sender, &mid);
    CHECK(n == 36 + 16 && wake_dgram_decode(buf, n, &m) == 0 && m.msg_type == WAKE_DGRAM_PT_IHAVE);
    CHECK(memcmp(m.msg_id.bytes, mid.bytes, sizeof(mid.bytes)) == 0);
    n = wake_dgram_encode_pt_ctrl(buf, sizeof(buf), WAKE_DGRAM_PT_GRAFT, sender, &mid);
    CHECK(n == 36 + 16 && wake_dgram_decode(buf, n, &m) == 0 && m.msg_type == WAKE_DGRAM_PT_GRAFT);
    n = wake_dgram_encode_pt_ctrl(buf, sizeof(buf), WAKE_DGRAM_PT_PRUNE, sender, NULL);
    CHECK(n == 36 && wake_dgram_decode(buf, n, &m) == 0 && m.msg_type == WAKE_DGRAM_PT_PRUNE);
    return 0;
}

static int test_missing_update_count_means_none(void) {
    uint8_t sender[WAKE_DGRAM_NODE_ID_LEN], buf[WAKE_DGRAM_HDR_SIZE];
    wake_dgram_t m;
    mk_id(sender, 0x07);
    CHECK(wake_dgram_encode_swim(buf, sizeof(buf), WAKE_DGRAM_SWIM_PING, sender, NULL, NULL, 0) == 0); /* no room for count */
    memset(buf, 0, sizeof(buf));
    buf[0] = 'W';
    buf[1] = 'D';
    buf[2] = WAKE_DGRAM_VERSION;
    buf[3] = WAKE_DGRAM_SWIM_PING;
    CHECK(wake_dgram_decode(buf, sizeof(buf), &m) == 0 && m.n_updates == 0);
    return 0;
}

static int test_rejects_malformed(void) {
    uint8_t sender[WAKE_DGRAM_NODE_ID_LEN], buf[WAKE_DGRAM_MAX_LEN], big[WAKE_DGRAM_MAX_LEN];
    wake_swim_update_t up[3];
    wake_plumtree_msg_id_t mid;
    wake_dgram_t m;
    size_t n;
    mk_id(sender, 0x08);
    mk_updates(up, 3);
    memset(mid.bytes, 1, sizeof(mid.bytes));

    CHECK(wake_dgram_decode(NULL, 40, &m) == -1);
    CHECK(wake_dgram_decode(buf, 40, NULL) == -1);
    CHECK(wake_dgram_decode(buf, WAKE_DGRAM_HDR_SIZE - 1, &m) == -1); /* short header */

    n = wake_dgram_encode_swim(buf, sizeof(buf), WAKE_DGRAM_SWIM_PING, sender, NULL, up, 3);
    memcpy(big, buf, n);
    big[0] = 'X';
    CHECK(wake_dgram_decode(big, n, &m) == -1); /* magic */
    memcpy(big, buf, n);
    big[2] = WAKE_DGRAM_VERSION + 1;
    CHECK(wake_dgram_decode(big, n, &m) == -1); /* version */
    memcpy(big, buf, n);
    big[3] = 7;
    CHECK(wake_dgram_decode(big, n, &m) == -1); /* unknown type */
    CHECK(wake_dgram_decode(buf, n - 1, &m) == -1); /* update list cut short */
    memcpy(big, buf, n);
    big[WAKE_DGRAM_HDR_SIZE] = WAKE_DGRAM_MAX_UPDATES + 1;
    CHECK(wake_dgram_decode(big, n, &m) == -1); /* count over the cap */

    n = wake_dgram_encode_pt_gossip(buf, sizeof(buf), sender, &mid, "0123456789", 10);
    CHECK(wake_dgram_decode(buf, n - 1, &m) == -1); /* payload cut short */
    memcpy(big, buf, n);
    big[36 + 16] = 0xff;
    big[36 + 17] = 0xff;
    CHECK(wake_dgram_decode(big, n, &m) == -1); /* payload length over the cap */

    n = wake_dgram_encode_pt_ctrl(buf, sizeof(buf), WAKE_DGRAM_PT_IHAVE, sender, &mid);
    CHECK(wake_dgram_decode(buf, n - 1, &m) == -1); /* message id cut short */
    n = wake_dgram_encode_swim(buf, sizeof(buf), WAKE_DGRAM_SWIM_PING_REQ, sender, sender, up, 1);
    CHECK(wake_dgram_decode(buf, WAKE_DGRAM_HDR_SIZE + 10, &m) == -1); /* target cut short */
    return 0;
}

static int test_encoders_refuse_a_small_buffer(void) {
    uint8_t sender[WAKE_DGRAM_NODE_ID_LEN], buf[420];
    wake_swim_update_t up[WAKE_DGRAM_MAX_UPDATES];
    wake_plumtree_msg_id_t mid;
    mk_id(sender, 0x09);
    mk_updates(up, WAKE_DGRAM_MAX_UPDATES);
    memset(mid.bytes, 2, sizeof(mid.bytes));
    CHECK(wake_dgram_encode_swim(buf, 420, WAKE_DGRAM_SWIM_PING, sender, NULL, up, WAKE_DGRAM_MAX_UPDATES) == 0);
    CHECK(wake_dgram_encode_pt_gossip(buf, 40, sender, &mid, "x", 1) == 0);
    CHECK(wake_dgram_encode_pt_ctrl(buf, 40, WAKE_DGRAM_PT_GRAFT, sender, &mid) == 0);
    CHECK(wake_dgram_encode_pt_ctrl(buf, 10, WAKE_DGRAM_PT_PRUNE, sender, NULL) == 0);
    return 0;
}

int main(void) {
    struct {
        const char *name;
        int (*fn)(void);
    } cases[] = {
        {"ping_with_max_updates", test_ping_with_max_updates},
        {"encoder_clamps_update_count", test_encoder_clamps_update_count},
        {"ping_req_carries_target", test_ping_req_carries_target},
        {"gossip_round_trip_and_alias", test_gossip_round_trip_and_alias},
        {"plumtree_control_messages", test_plumtree_control_messages},
        {"missing_update_count_means_none", test_missing_update_count_means_none},
        {"rejects_malformed", test_rejects_malformed},
        {"encoders_refuse_a_small_buffer", test_encoders_refuse_a_small_buffer},
    };
    int n = (int)(sizeof(cases) / sizeof(cases[0])), i, passed = 0;
    for (i = 0; i < n; i++)
        if (cases[i].fn() == 0) {
            printf("  ok   %s\n", cases[i].name);
            passed++;
        }
    printf("test_dgram: %d/%d passed\n", passed, n);
    return g_fail ? 1 : 0;
}
