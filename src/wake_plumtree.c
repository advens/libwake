/*
 * wake_plumtree.c: WAKE PlumTree Epidemic Broadcast implementation
 *
 * Push-Lazy-Push Multicast Tree: builds an overlay spanning tree for
 * efficient broadcast with epidemic backup for tree repair.
 *
 * Single-threaded, event-driven. No network I/O: callbacks only.
 *
 * Copyright (c) 2026 Advens. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "wake_plumtree.h"

#include <stdlib.h>
#include <string.h>

/* --------------------------------------------------------------------------
 * Internal helpers
 * -------------------------------------------------------------------------- */

static bool
is_self(const wake_plumtree_t *pt,
        const uint8_t node_id[WAKE_PLUMTREE_NODE_ID_LEN])
{
    return memcmp(pt->self_id, node_id, WAKE_PLUMTREE_NODE_ID_LEN) == 0;
}

static int
find_peer(const wake_plumtree_t *pt,
          const uint8_t node_id[WAKE_PLUMTREE_NODE_ID_LEN])
{
    for (uint32_t i = 0; i < pt->peer_count; i++) {
        if (memcmp(pt->peers[i].node_id, node_id,
                   WAKE_PLUMTREE_NODE_ID_LEN) == 0)
            return (int)i;
    }
    return -1;
}

/* --------------------------------------------------------------------------
 * Message cache operations
 * -------------------------------------------------------------------------- */

static wake_plumtree_cache_entry_t *
cache_find(const wake_plumtree_t *pt, const wake_plumtree_msg_id_t *msg_id)
{
    for (uint32_t i = 0; i < pt->config.cache_size; i++) {
        if (pt->cache[i].occupied &&
            wake_plumtree_msg_id_eq(&pt->cache[i].msg_id, msg_id))
            return &pt->cache[i];
    }
    return NULL;
}

static wake_plumtree_cache_entry_t *
cache_insert(wake_plumtree_t *pt, const wake_plumtree_msg_id_t *msg_id,
             const void *payload, uint32_t payload_len, uint64_t now_ms)
{
    /* Clamp payload to max */
    if (payload_len > WAKE_PLUMTREE_MAX_PAYLOAD)
        payload_len = WAKE_PLUMTREE_MAX_PAYLOAD;

    /* Find empty slot */
    for (uint32_t i = 0; i < pt->config.cache_size; i++) {
        if (!pt->cache[i].occupied) {
            wake_plumtree_cache_entry_t *e = &pt->cache[i];
            e->msg_id      = *msg_id;
            e->received_ms = now_ms;
            e->payload_len = (uint16_t)payload_len;
            e->occupied    = 1;
            memset(e->_pad, 0, sizeof(e->_pad));
            memcpy(e->payload, payload, payload_len);
            if (payload_len < WAKE_PLUMTREE_MAX_PAYLOAD)
                memset(e->payload + payload_len, 0,
                       WAKE_PLUMTREE_MAX_PAYLOAD - payload_len);
            pt->cache_count++;
            return e;
        }
    }

    /* Full: evict oldest */
    uint32_t oldest = 0;
    for (uint32_t i = 1; i < pt->config.cache_size; i++) {
        if (pt->cache[i].occupied &&
            pt->cache[i].received_ms < pt->cache[oldest].received_ms)
            oldest = i;
    }

    wake_plumtree_cache_entry_t *e = &pt->cache[oldest];
    e->msg_id      = *msg_id;
    e->received_ms = now_ms;
    e->payload_len = (uint16_t)payload_len;
    e->occupied    = 1;
    memcpy(e->payload, payload, payload_len);
    if (payload_len < WAKE_PLUMTREE_MAX_PAYLOAD)
        memset(e->payload + payload_len, 0,
               WAKE_PLUMTREE_MAX_PAYLOAD - payload_len);
    pt->cache_evictions++;
    return e;
}

/* --------------------------------------------------------------------------
 * Pending IHAVE operations
 * -------------------------------------------------------------------------- */

static wake_plumtree_pending_t *
pending_find(const wake_plumtree_t *pt, const wake_plumtree_msg_id_t *msg_id)
{
    for (uint32_t i = 0; i < pt->config.pending_size; i++) {
        if (pt->pending[i].active &&
            wake_plumtree_msg_id_eq(&pt->pending[i].msg_id, msg_id))
            return &pt->pending[i];
    }
    return NULL;
}

static void
pending_add(wake_plumtree_t *pt,
            const wake_plumtree_msg_id_t *msg_id,
            const uint8_t from_id[WAKE_PLUMTREE_NODE_ID_LEN],
            uint64_t now_ms)
{
    /* Update existing entry for same msg_id */
    wake_plumtree_pending_t *existing = pending_find(pt, msg_id);
    if (existing) {
        memcpy(existing->from_id, from_id, WAKE_PLUMTREE_NODE_ID_LEN);
        existing->received_ms = now_ms;
        return;
    }

    /* Find empty slot */
    for (uint32_t i = 0; i < pt->config.pending_size; i++) {
        if (!pt->pending[i].active) {
            wake_plumtree_pending_t *p = &pt->pending[i];
            p->msg_id = *msg_id;
            memcpy(p->from_id, from_id, WAKE_PLUMTREE_NODE_ID_LEN);
            p->received_ms = now_ms;
            p->active      = 1;
            memset(p->_pad, 0, sizeof(p->_pad));
            pt->pending_count++;
            return;
        }
    }

    /* Full: evict oldest */
    uint32_t oldest = 0;
    bool found = false;
    for (uint32_t i = 0; i < pt->config.pending_size; i++) {
        if (pt->pending[i].active) {
            if (!found || pt->pending[i].received_ms <
                          pt->pending[oldest].received_ms) {
                oldest = i;
                found = true;
            }
        }
    }

    if (found) {
        wake_plumtree_pending_t *p = &pt->pending[oldest];
        p->msg_id = *msg_id;
        memcpy(p->from_id, from_id, WAKE_PLUMTREE_NODE_ID_LEN);
        p->received_ms = now_ms;
        p->active      = 1;
    }
}

static void
pending_remove_msg(wake_plumtree_t *pt, const wake_plumtree_msg_id_t *msg_id)
{
    for (uint32_t i = 0; i < pt->config.pending_size; i++) {
        if (pt->pending[i].active &&
            wake_plumtree_msg_id_eq(&pt->pending[i].msg_id, msg_id)) {
            pt->pending[i].active = 0;
            if (pt->pending_count > 0)
                pt->pending_count--;
            return;
        }
    }
}

/* Promote a peer to EAGER. */
static void
promote_eager(wake_plumtree_t *pt,
              const uint8_t node_id[WAKE_PLUMTREE_NODE_ID_LEN],
              uint64_t now_ms)
{
    int idx = find_peer(pt, node_id);
    if (idx >= 0) {
        pt->peers[idx].link_type = WAKE_PT_EAGER;
        pt->peers[idx].last_active_ms = now_ms;
    }
}

/* Demote a peer to LAZY. */
static void
demote_lazy(wake_plumtree_t *pt,
            const uint8_t node_id[WAKE_PLUMTREE_NODE_ID_LEN],
            uint64_t now_ms)
{
    int idx = find_peer(pt, node_id);
    if (idx >= 0) {
        pt->peers[idx].link_type = WAKE_PT_LAZY;
        pt->peers[idx].last_active_ms = now_ms;
    }
}

/* --------------------------------------------------------------------------
 * Default configuration
 * -------------------------------------------------------------------------- */

wake_plumtree_config_t
wake_plumtree_default_config(void)
{
    wake_plumtree_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.max_peers       = 512;
    cfg.cache_size      = 1024;
    cfg.pending_size    = 256;
    cfg.lazy_timeout_ms = 5000;
    cfg.cache_ttl_ms    = 60000;
    return cfg;
}

/* --------------------------------------------------------------------------
 * Lifecycle
 * -------------------------------------------------------------------------- */

wake_plumtree_t *
wake_plumtree_create(const uint8_t self_id[WAKE_PLUMTREE_NODE_ID_LEN],
                      const wake_plumtree_config_t *cfg)
{
    if (!self_id)
        return NULL;

    wake_plumtree_t *pt = calloc(1, sizeof(wake_plumtree_t));
    if (!pt)
        return NULL;

    pt->config = cfg ? *cfg : wake_plumtree_default_config();

    if (pt->config.max_peers == 0)
        pt->config.max_peers = 512;
    if (pt->config.cache_size == 0)
        pt->config.cache_size = 1024;
    if (pt->config.pending_size == 0)
        pt->config.pending_size = 256;
    if (pt->config.lazy_timeout_ms == 0)
        pt->config.lazy_timeout_ms = 5000;
    if (pt->config.cache_ttl_ms == 0)
        pt->config.cache_ttl_ms = 60000;

    pt->peers = calloc(pt->config.max_peers,
                        sizeof(wake_plumtree_peer_t));
    pt->cache = calloc(pt->config.cache_size,
                        sizeof(wake_plumtree_cache_entry_t));
    pt->pending = calloc(pt->config.pending_size,
                          sizeof(wake_plumtree_pending_t));

    if (!pt->peers || !pt->cache || !pt->pending) {
        free(pt->peers);
        free(pt->cache);
        free(pt->pending);
        free(pt);
        return NULL;
    }

    memcpy(pt->self_id, self_id, WAKE_PLUMTREE_NODE_ID_LEN);
    return pt;
}

void
wake_plumtree_destroy(wake_plumtree_t *pt)
{
    if (!pt)
        return;
    free(pt->peers);
    free(pt->cache);
    free(pt->pending);
    free(pt);
}

void
wake_plumtree_reset(wake_plumtree_t *pt)
{
    if (!pt)
        return;
    memset(pt->peers, 0,
           (size_t)pt->config.max_peers * sizeof(wake_plumtree_peer_t));
    memset(pt->cache, 0,
           (size_t)pt->config.cache_size * sizeof(wake_plumtree_cache_entry_t));
    memset(pt->pending, 0,
           (size_t)pt->config.pending_size * sizeof(wake_plumtree_pending_t));
    pt->peer_count    = 0;
    pt->cache_count   = 0;
    pt->pending_count = 0;
    pt->messages_received  = 0;
    pt->messages_broadcast = 0;
    pt->duplicates      = 0;
    pt->grafts_sent     = 0;
    pt->prunes_sent     = 0;
    pt->repairs         = 0;
    pt->cache_evictions = 0;
}

/* --------------------------------------------------------------------------
 * Peer management
 * -------------------------------------------------------------------------- */

wake_plumtree_result_t
wake_plumtree_add_peer(wake_plumtree_t *pt,
                        const uint8_t node_id[WAKE_PLUMTREE_NODE_ID_LEN],
                        uint64_t now_ms)
{
    if (!pt || !node_id)
        return WAKE_PT_NOT_FOUND;

    if (is_self(pt, node_id))
        return WAKE_PT_SELF;

    if (find_peer(pt, node_id) >= 0)
        return WAKE_PT_EXISTS;

    if (pt->peer_count >= pt->config.max_peers)
        return WAKE_PT_FULL;

    wake_plumtree_peer_t *p = &pt->peers[pt->peer_count];
    memset(p, 0, sizeof(*p));
    memcpy(p->node_id, node_id, WAKE_PLUMTREE_NODE_ID_LEN);
    p->last_active_ms = now_ms;
    p->link_type      = WAKE_PT_EAGER;  /* New peers start EAGER */
    pt->peer_count++;
    return WAKE_PT_OK;
}

wake_plumtree_result_t
wake_plumtree_remove_peer(wake_plumtree_t *pt,
                           const uint8_t node_id[WAKE_PLUMTREE_NODE_ID_LEN])
{
    if (!pt || !node_id)
        return WAKE_PT_NOT_FOUND;

    int idx = find_peer(pt, node_id);
    if (idx < 0)
        return WAKE_PT_NOT_FOUND;

    /* Compact: shift last element into the gap */
    uint32_t last = pt->peer_count - 1;
    if ((uint32_t)idx != last) {
        pt->peers[idx] = pt->peers[last];
    }
    memset(&pt->peers[last], 0, sizeof(wake_plumtree_peer_t));
    pt->peer_count--;

    return WAKE_PT_OK;
}

int
wake_plumtree_peer_link(const wake_plumtree_t *pt,
                         const uint8_t node_id[WAKE_PLUMTREE_NODE_ID_LEN])
{
    if (!pt || !node_id)
        return -1;

    int idx = find_peer(pt, node_id);
    if (idx < 0)
        return -1;

    return (int)pt->peers[idx].link_type;
}

/* --------------------------------------------------------------------------
 * Broadcast (local origination)
 * -------------------------------------------------------------------------- */

void
wake_plumtree_broadcast(wake_plumtree_t *pt,
                         const wake_plumtree_msg_id_t *msg_id,
                         const void *payload,
                         uint32_t payload_len,
                         uint64_t now_ms,
                         wake_plumtree_send_fn send_fn,
                         void *ctx)
{
    if (!pt || !msg_id || !payload || payload_len == 0)
        return;

    /* Cache the message */
    cache_insert(pt, msg_id, payload, payload_len, now_ms);

    pt->messages_broadcast++;

    /* Send to all peers */
    for (uint32_t i = 0; i < pt->peer_count; i++) {
        if (pt->peers[i].link_type == WAKE_PT_EAGER) {
            if (send_fn)
                send_fn(WAKE_PT_GOSSIP, pt->peers[i].node_id,
                        msg_id, payload, payload_len, ctx);
        } else {
            if (send_fn)
                send_fn(WAKE_PT_IHAVE, pt->peers[i].node_id,
                        msg_id, NULL, 0, ctx);
        }
    }
}

/* --------------------------------------------------------------------------
 * Protocol message handlers
 * -------------------------------------------------------------------------- */

bool
wake_plumtree_recv_gossip(wake_plumtree_t *pt,
                           const uint8_t from_id[WAKE_PLUMTREE_NODE_ID_LEN],
                           const wake_plumtree_msg_id_t *msg_id,
                           const void *payload,
                           uint32_t payload_len,
                           uint64_t now_ms,
                           wake_plumtree_send_fn send_fn,
                           wake_plumtree_deliver_fn deliver_fn,
                           void *ctx)
{
    if (!pt || !from_id || !msg_id || !payload)
        return false;

    pt->messages_received++;

    /* Check if duplicate */
    if (cache_find(pt, msg_id) != NULL) {
        /* Duplicate: PRUNE the sender */
        pt->duplicates++;
        if (send_fn)
            send_fn(WAKE_PT_PRUNE, from_id, msg_id, NULL, 0, ctx);
        pt->prunes_sent++;

        /*
         * Optimization: ensure the sender is LAZY in our list.
         * (They may already be if we previously pruned them.)
         */
        demote_lazy(pt, from_id, now_ms);
        return false;
    }

    /* New message: cache it */
    cache_insert(pt, msg_id, payload, payload_len, now_ms);

    /* Cancel any pending IHAVE for this message */
    pending_remove_msg(pt, msg_id);

    /* Ensure sender is EAGER (they delivered successfully) */
    promote_eager(pt, from_id, now_ms);

    /* Deliver to application */
    if (deliver_fn)
        deliver_fn(msg_id, payload, payload_len, from_id, ctx);

    /* Forward to other EAGER peers (not the sender) */
    for (uint32_t i = 0; i < pt->peer_count; i++) {
        if (memcmp(pt->peers[i].node_id, from_id,
                   WAKE_PLUMTREE_NODE_ID_LEN) == 0)
            continue; /* skip sender */

        if (pt->peers[i].link_type == WAKE_PT_EAGER) {
            if (send_fn)
                send_fn(WAKE_PT_GOSSIP, pt->peers[i].node_id,
                        msg_id, payload, payload_len, ctx);
        } else {
            if (send_fn)
                send_fn(WAKE_PT_IHAVE, pt->peers[i].node_id,
                        msg_id, NULL, 0, ctx);
        }
    }

    return true;
}

void
wake_plumtree_recv_ihave(wake_plumtree_t *pt,
                          const uint8_t from_id[WAKE_PLUMTREE_NODE_ID_LEN],
                          const wake_plumtree_msg_id_t *msg_id,
                          uint64_t now_ms)
{
    if (!pt || !from_id || !msg_id)
        return;

    /* If we already have the message, ignore */
    if (cache_find(pt, msg_id) != NULL)
        return;

    /* Record pending IHAVE for lazy repair */
    pending_add(pt, msg_id, from_id, now_ms);
}

void
wake_plumtree_recv_graft(wake_plumtree_t *pt,
                          const uint8_t from_id[WAKE_PLUMTREE_NODE_ID_LEN],
                          const wake_plumtree_msg_id_t *msg_id,
                          uint64_t now_ms,
                          wake_plumtree_send_fn send_fn,
                          void *ctx)
{
    if (!pt || !from_id || !msg_id)
        return;

    /* Promote sender to EAGER (bidirectional tree edge) */
    promote_eager(pt, from_id, now_ms);

    /* If we have the message, send it */
    const wake_plumtree_cache_entry_t *e = cache_find(pt, msg_id);
    if (e && send_fn) {
        send_fn(WAKE_PT_GOSSIP, from_id, msg_id,
                e->payload, e->payload_len, ctx);
    }

    pt->repairs++;
}

void
wake_plumtree_recv_prune(wake_plumtree_t *pt,
                          const uint8_t from_id[WAKE_PLUMTREE_NODE_ID_LEN],
                          uint64_t now_ms)
{
    if (!pt || !from_id)
        return;

    /* Demote sender to LAZY */
    demote_lazy(pt, from_id, now_ms);
}

/* --------------------------------------------------------------------------
 * Timer tick
 * -------------------------------------------------------------------------- */

uint32_t
wake_plumtree_tick(wake_plumtree_t *pt,
                    uint64_t now_ms,
                    wake_plumtree_send_fn send_fn,
                    void *ctx)
{
    if (!pt)
        return 0;

    uint32_t grafts = 0;

    /* Check pending IHAVEs for timeout → GRAFT */
    for (uint32_t i = 0; i < pt->config.pending_size; i++) {
        wake_plumtree_pending_t *p = &pt->pending[i];
        if (!p->active)
            continue;

        if (now_ms - p->received_ms >= (uint64_t)pt->config.lazy_timeout_ms) {
            /* Timeout: send GRAFT and promote to eager */
            if (send_fn) {
                send_fn(WAKE_PT_GRAFT, p->from_id, &p->msg_id,
                        NULL, 0, ctx);
            }
            promote_eager(pt, p->from_id, now_ms);
            pt->grafts_sent++;
            grafts++;

            /* Remove from pending */
            p->active = 0;
            if (pt->pending_count > 0)
                pt->pending_count--;
        }
    }

    /* Evict expired cache entries */
    if (pt->config.cache_ttl_ms > 0) {
        for (uint32_t i = 0; i < pt->config.cache_size; i++) {
            if (pt->cache[i].occupied &&
                now_ms - pt->cache[i].received_ms >=
                    (uint64_t)pt->config.cache_ttl_ms) {
                pt->cache[i].occupied = 0;
                if (pt->cache_count > 0)
                    pt->cache_count--;
                pt->cache_evictions++;
            }
        }
    }

    return grafts;
}

/* --------------------------------------------------------------------------
 * Inspection
 * -------------------------------------------------------------------------- */

void
wake_plumtree_stats(const wake_plumtree_t *pt,
                     wake_plumtree_stats_t *out)
{
    if (!out)
        return;
    memset(out, 0, sizeof(*out));
    if (!pt)
        return;

    out->peer_count = pt->peer_count;
    for (uint32_t i = 0; i < pt->peer_count; i++) {
        if (pt->peers[i].link_type == WAKE_PT_EAGER)
            out->eager_count++;
        else
            out->lazy_count++;
    }
    out->cache_entries  = pt->cache_count;
    out->pending_ihaves = pt->pending_count;

    out->messages_received  = pt->messages_received;
    out->messages_broadcast = pt->messages_broadcast;
    out->duplicates         = pt->duplicates;
    out->grafts_sent        = pt->grafts_sent;
    out->prunes_sent        = pt->prunes_sent;
    out->repairs            = pt->repairs;
    out->cache_evictions    = pt->cache_evictions;
}

bool
wake_plumtree_has_msg(const wake_plumtree_t *pt,
                       const wake_plumtree_msg_id_t *msg_id)
{
    if (!pt || !msg_id)
        return false;
    return cache_find(pt, msg_id) != NULL;
}

/* --------------------------------------------------------------------------
 * Name accessors
 * -------------------------------------------------------------------------- */

static const char *link_names[] = { "EAGER", "LAZY" };
static const char *msg_type_names[] = { "GOSSIP", "IHAVE", "GRAFT", "PRUNE" };
static const char *result_names[] = {
    "OK", "EXISTS", "NOT_FOUND", "FULL", "SELF", "DUP"
};

const char *
wake_plumtree_link_name(wake_plumtree_link_t link)
{
    if ((unsigned)link <= 1)
        return link_names[(unsigned)link];
    return "UNKNOWN";
}

const char *
wake_plumtree_msg_type_name(wake_plumtree_msg_type_t type)
{
    if ((unsigned)type < WAKE_PT__COUNT)
        return msg_type_names[(unsigned)type];
    return "UNKNOWN";
}

const char *
wake_plumtree_result_name(wake_plumtree_result_t r)
{
    if ((unsigned)r <= 5)
        return result_names[(unsigned)r];
    return "UNKNOWN";
}
