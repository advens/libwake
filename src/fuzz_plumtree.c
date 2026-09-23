/*
 * fuzz_plumtree.c - libFuzzer: untrusted overlay recv path.
 *
 * First byte selects GOSSIP/IHAVE/GRAFT/PRUNE. The rest is peer id,
 * msg_id, and payload. Callbacks are no-ops. Must not crash or
 * overflow the cache.
 *
 * Copyright (c) 2026 Advens. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "wake_plumtree.h"

#include <stdint.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static void
send_nop(wake_plumtree_msg_type_t type,
         const uint8_t target_id[WAKE_PLUMTREE_NODE_ID_LEN],
         const wake_plumtree_msg_id_t *msg_id,
         const void *payload, uint32_t payload_len, void *ctx)
{
    (void)type;
    (void)target_id;
    (void)msg_id;
    (void)payload;
    (void)payload_len;
    (void)ctx;
}

static void
deliver_nop(const wake_plumtree_msg_id_t *msg_id,
            const void *payload, uint32_t payload_len,
            const uint8_t from_id[WAKE_PLUMTREE_NODE_ID_LEN], void *ctx)
{
    (void)msg_id;
    (void)payload;
    (void)payload_len;
    (void)from_id;
    (void)ctx;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static const uint8_t self[WAKE_PLUMTREE_NODE_ID_LEN] = {1};
    uint8_t peer[WAKE_PLUMTREE_NODE_ID_LEN];
    wake_plumtree_config_t cfg;
    wake_plumtree_t *pt;
    wake_plumtree_msg_id_t mid;
    uint8_t kind;
    const uint8_t *p;
    size_t left;

    if (size == 0) {
        return 0;
    }

    memset(&cfg, 0, sizeof(cfg));
    cfg.max_peers = 8;
    cfg.cache_size = 16;
    cfg.pending_size = 8;
    cfg.lazy_timeout_ms = 50;
    cfg.cache_ttl_ms = 200;

    pt = wake_plumtree_create(self, &cfg);
    if (pt == NULL) {
        return 0;
    }

    memset(peer, 2, sizeof(peer));
    (void)wake_plumtree_add_peer(pt, peer, 1);

    kind = data[0] % WAKE_PT__COUNT;
    p = data + 1;
    left = size - 1;
    memset(&mid, 0, sizeof(mid));
    if (left >= WAKE_PLUMTREE_MSG_ID_LEN) {
        memcpy(mid.bytes, p, WAKE_PLUMTREE_MSG_ID_LEN);
        p += WAKE_PLUMTREE_MSG_ID_LEN;
        left -= WAKE_PLUMTREE_MSG_ID_LEN;
    }
    if (left >= WAKE_PLUMTREE_NODE_ID_LEN) {
        memcpy(peer, p, WAKE_PLUMTREE_NODE_ID_LEN);
        p += WAKE_PLUMTREE_NODE_ID_LEN;
        left -= WAKE_PLUMTREE_NODE_ID_LEN;
        (void)wake_plumtree_add_peer(pt, peer, 1);
    }
    if (left > WAKE_PLUMTREE_MAX_PAYLOAD) {
        left = WAKE_PLUMTREE_MAX_PAYLOAD;
    }

    switch (kind) {
    case WAKE_PT_GOSSIP:
        (void)wake_plumtree_recv_gossip(pt, peer, &mid, p, (uint32_t)left,
                                        10, send_nop, deliver_nop, NULL);
        break;
    case WAKE_PT_IHAVE:
        wake_plumtree_recv_ihave(pt, peer, &mid, 10);
        break;
    case WAKE_PT_GRAFT:
        wake_plumtree_recv_graft(pt, peer, &mid, 10, send_nop, NULL);
        break;
    default:
        wake_plumtree_recv_prune(pt, peer, 10);
        break;
    }
    (void)wake_plumtree_tick(pt, 100, send_nop, NULL);
    wake_plumtree_destroy(pt);
    return 0;
}
