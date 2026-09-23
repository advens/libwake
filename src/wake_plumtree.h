/*
 * wake_plumtree.h: WAKE PlumTree Epidemic Broadcast
 *
 * Push-Lazy-Push Multicast Tree for reliable broadcast of threat signals
 * across the WAKE mesh. Builds an overlay spanning tree with epidemic
 * backup for fault tolerance.
 *
 * How it works:
 *
 *   Each peer is classified as EAGER or LAZY. New peers start EAGER.
 *
 *   - EAGER peers receive full messages immediately (GOSSIP).
 *   - LAZY peers receive only message IDs (IHAVE).
 *
 *   On duplicate: sender is PRUNED (demoted to LAZY). This naturally
 *   forms a spanning tree; each node receives each message exactly
 *   once via an EAGER link, with LAZY links as backup.
 *
 *   On missing message (IHAVE without prior GOSSIP): after a timeout,
 *   GRAFT the IHAVE source (promote to EAGER and request the message).
 *   This repairs tree partitions automatically.
 *
 * Protocol messages:
 *   GOSSIP: full message (msg_id + payload), sent to EAGER peers
 *   IHAVE: message notification (msg_id only), sent to LAZY peers
 *   GRAFT: repair request (msg_id), promotes peer to EAGER
 *   PRUNE: demotion request, moves peer to LAZY
 *
 * Bio-inspiration: mycorrhizal networks. Trees in a forest share
 * nutrients through underground fungal networks. The spanning tree
 * is the primary transport (like mycorrhizal hyphae), while lazy
 * links are dormant connections that activate when the primary
 * path is disrupted.
 *
 * Network I/O is NOT in this module; it provides the state machine.
 * The host application performs the actual message sending via callbacks.
 *
 * Scale: this tree is built directly over wake_swim.h's dense, full-view
 * membership list; see the "Scale" note there. Efficient at the same
 * O(100)-O(1000) node range; larger meshes need a partial-view peer-sampling
 * layer (e.g. HyParView) feeding the peer set instead.
 *
 * Copyright (c) 2026 Advens. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef WAKE_PLUMTREE_H
#define WAKE_PLUMTREE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/* --------------------------------------------------------------------------
 * Constants
 * -------------------------------------------------------------------------- */

#define WAKE_PLUMTREE_NODE_ID_LEN  32
#define WAKE_PLUMTREE_MSG_ID_LEN   16
#define WAKE_PLUMTREE_MAX_PAYLOAD   256   /* covers wake_signal_t (192B) */

/* --------------------------------------------------------------------------
 * Link types
 * -------------------------------------------------------------------------- */
typedef enum {
    WAKE_PT_EAGER = 0,  /* Tree edge: receives full messages       */
    WAKE_PT_LAZY  = 1,  /* Backup edge: receives IHAVE only        */
} wake_plumtree_link_t;

/* --------------------------------------------------------------------------
 * Protocol message types
 * -------------------------------------------------------------------------- */
typedef enum {
    WAKE_PT_GOSSIP = 0,  /* Full message: msg_id + payload          */
    WAKE_PT_IHAVE  = 1,  /* Message notification: msg_id only       */
    WAKE_PT_GRAFT  = 2,  /* Repair: request message + promote       */
    WAKE_PT_PRUNE  = 3,  /* Demotion: move sender to lazy           */
    WAKE_PT__COUNT = 4
} wake_plumtree_msg_type_t;

/* --------------------------------------------------------------------------
 * Operation results
 * -------------------------------------------------------------------------- */
typedef enum {
    WAKE_PT_OK        = 0,
    WAKE_PT_EXISTS    = 1,
    WAKE_PT_NOT_FOUND = 2,
    WAKE_PT_FULL      = 3,
    WAKE_PT_SELF      = 4,
    WAKE_PT_DUP       = 5,  /* Message already seen (duplicate) */
} wake_plumtree_result_t;

/* --------------------------------------------------------------------------
 * Message ID: 16-byte opaque identifier
 * -------------------------------------------------------------------------- */
typedef struct {
    uint8_t bytes[WAKE_PLUMTREE_MSG_ID_LEN];
} wake_plumtree_msg_id_t;

static inline bool
wake_plumtree_msg_id_eq(const wake_plumtree_msg_id_t *a,
                         const wake_plumtree_msg_id_t *b)
{
    return memcmp(a->bytes, b->bytes, WAKE_PLUMTREE_MSG_ID_LEN) == 0;
}

/* --------------------------------------------------------------------------
 * Peer entry: 48 bytes
 * -------------------------------------------------------------------------- */
typedef struct {
    uint8_t  node_id[WAKE_PLUMTREE_NODE_ID_LEN]; /* 32B */
    uint64_t last_active_ms;  /*  8B: last protocol activity timestamp */
    uint8_t  link_type;       /*  1B: wake_plumtree_link_t             */
    uint8_t  _pad[7];         /*  7B                                   */
} wake_plumtree_peer_t;

_Static_assert(sizeof(wake_plumtree_peer_t) == 48,
    "plumtree peer must be exactly 48 bytes");

/* --------------------------------------------------------------------------
 * Cache entry: 288 bytes
 *
 * Stores full message payload for GRAFT responses. Fixed-size to
 * avoid per-message heap allocation.
 * -------------------------------------------------------------------------- */
typedef struct {
    wake_plumtree_msg_id_t msg_id;   /* 16B */
    uint64_t received_ms;            /*  8B */
    uint16_t payload_len;            /*  2B */
    uint8_t  occupied;               /*  1B */
    uint8_t  _pad[5];               /*  5B */
    uint8_t  payload[WAKE_PLUMTREE_MAX_PAYLOAD]; /* 256B */
} wake_plumtree_cache_entry_t;

_Static_assert(sizeof(wake_plumtree_cache_entry_t) == 288,
    "plumtree cache entry must be exactly 288 bytes");

/* --------------------------------------------------------------------------
 * Pending IHAVE: 64 bytes
 *
 * Tracks an IHAVE we received but haven't seen the full message for.
 * After lazy_timeout_ms, triggers a GRAFT to the source peer.
 * -------------------------------------------------------------------------- */
typedef struct {
    wake_plumtree_msg_id_t msg_id;   /* 16B */
    uint8_t  from_id[WAKE_PLUMTREE_NODE_ID_LEN]; /* 32B */
    uint64_t received_ms;            /*  8B */
    uint8_t  active;                 /*  1B */
    uint8_t  _pad[7];               /*  7B */
} wake_plumtree_pending_t;

_Static_assert(sizeof(wake_plumtree_pending_t) == 64,
    "plumtree pending must be exactly 64 bytes");

/* --------------------------------------------------------------------------
 * Configuration: 32 bytes
 *
 * Default values tuned for ~450 nodes with rare signal
 * emission (quorum crossings, not every log event).
 * -------------------------------------------------------------------------- */
typedef struct {
    uint16_t max_peers;           /* Max peers (default: 512)            */
    uint16_t cache_size;          /* Message cache entries (default: 1024) */
    uint16_t pending_size;        /* Max pending IHAVEs (default: 256)   */
    uint16_t _pad0;
    uint32_t lazy_timeout_ms;     /* IHAVE→GRAFT timeout (default: 5000) */
    uint32_t cache_ttl_ms;        /* Cache entry TTL (default: 60000)    */
    uint8_t  _reserved[16];
} wake_plumtree_config_t;

_Static_assert(sizeof(wake_plumtree_config_t) == 32,
    "plumtree config must be exactly 32 bytes");

/* --------------------------------------------------------------------------
 * Statistics snapshot
 * -------------------------------------------------------------------------- */
typedef struct {
    uint32_t peer_count;
    uint32_t eager_count;
    uint32_t lazy_count;
    uint32_t cache_entries;
    uint32_t pending_ihaves;
    uint32_t _pad0;
    uint64_t messages_received;
    uint64_t messages_broadcast;
    uint64_t duplicates;
    uint64_t grafts_sent;
    uint64_t prunes_sent;
    uint64_t repairs;
    uint64_t cache_evictions;
} wake_plumtree_stats_t;

/* --------------------------------------------------------------------------
 * Main PlumTree state (owned by the host application, single-threaded)
 * -------------------------------------------------------------------------- */
typedef struct {
    wake_plumtree_config_t config;

    uint8_t self_id[WAKE_PLUMTREE_NODE_ID_LEN];

    /* Peer list (dense array) */
    wake_plumtree_peer_t *peers;
    uint32_t              peer_count;

    /* Message cache (dedup + GRAFT responses) */
    wake_plumtree_cache_entry_t *cache;
    uint32_t                     cache_count;

    /* Pending IHAVEs (awaiting lazy timeout) */
    wake_plumtree_pending_t *pending;
    uint32_t                 pending_count;

    /* Lifetime counters */
    uint64_t messages_received;
    uint64_t messages_broadcast;
    uint64_t duplicates;
    uint64_t grafts_sent;
    uint64_t prunes_sent;
    uint64_t repairs;
    uint64_t cache_evictions;
} wake_plumtree_t;

/* --------------------------------------------------------------------------
 * Callbacks
 * -------------------------------------------------------------------------- */

/*
 * Send callback: called when PlumTree needs to send a protocol message.
 *
 * type:        GOSSIP, IHAVE, GRAFT, or PRUNE
 * target_id:   peer to send to (32 bytes)
 * msg_id:      message identifier (NULL only for PRUNE)
 * payload:     message body (non-NULL only for GOSSIP)
 * payload_len: payload size (>0 only for GOSSIP)
 * ctx:         caller-provided context
 */
typedef void (*wake_plumtree_send_fn)(
    wake_plumtree_msg_type_t type,
    const uint8_t target_id[WAKE_PLUMTREE_NODE_ID_LEN],
    const wake_plumtree_msg_id_t *msg_id,
    const void *payload,
    uint32_t payload_len,
    void *ctx);

/*
 * Deliver callback: called when a new (non-duplicate) message arrives.
 *
 * msg_id:      message identifier
 * payload:     message body
 * payload_len: payload size
 * from_id:     peer that sent it to us
 * ctx:         caller-provided context
 */
typedef void (*wake_plumtree_deliver_fn)(
    const wake_plumtree_msg_id_t *msg_id,
    const void *payload,
    uint32_t payload_len,
    const uint8_t from_id[WAKE_PLUMTREE_NODE_ID_LEN],
    void *ctx);

/* --------------------------------------------------------------------------
 * Configuration
 * -------------------------------------------------------------------------- */

wake_plumtree_config_t wake_plumtree_default_config(void);

/* --------------------------------------------------------------------------
 * Lifecycle
 * -------------------------------------------------------------------------- */

wake_plumtree_t *wake_plumtree_create(
    const uint8_t self_id[WAKE_PLUMTREE_NODE_ID_LEN],
    const wake_plumtree_config_t *cfg);

void wake_plumtree_destroy(wake_plumtree_t *pt);
void wake_plumtree_reset(wake_plumtree_t *pt);

/* --------------------------------------------------------------------------
 * Peer management (driven by SWIM membership events)
 * -------------------------------------------------------------------------- */

/*
 * Add a peer. New peers start as EAGER.
 * Returns WAKE_PT_OK, WAKE_PT_EXISTS, WAKE_PT_FULL, or WAKE_PT_SELF.
 */
wake_plumtree_result_t wake_plumtree_add_peer(
    wake_plumtree_t *pt,
    const uint8_t node_id[WAKE_PLUMTREE_NODE_ID_LEN],
    uint64_t now_ms);

/*
 * Remove a peer. Compacts the array.
 * Returns WAKE_PT_OK or WAKE_PT_NOT_FOUND.
 */
wake_plumtree_result_t wake_plumtree_remove_peer(
    wake_plumtree_t *pt,
    const uint8_t node_id[WAKE_PLUMTREE_NODE_ID_LEN]);

/*
 * Query a peer's link type.
 * Returns EAGER/LAZY, or -1 if not found.
 */
int wake_plumtree_peer_link(const wake_plumtree_t *pt,
                             const uint8_t node_id[WAKE_PLUMTREE_NODE_ID_LEN]);

/* --------------------------------------------------------------------------
 * Broadcast (originate a message locally)
 *
 * Sends GOSSIP to all EAGER peers and IHAVE to all LAZY peers.
 * Adds message to local cache for GRAFT responses.
 * -------------------------------------------------------------------------- */

void wake_plumtree_broadcast(
    wake_plumtree_t *pt,
    const wake_plumtree_msg_id_t *msg_id,
    const void *payload,
    uint32_t payload_len,
    uint64_t now_ms,
    wake_plumtree_send_fn send_fn,
    void *ctx);

/* --------------------------------------------------------------------------
 * Protocol message handlers
 *
 * Called by the host application when a message arrives from the network.
 * These drive the PlumTree state machine and may invoke callbacks.
 * -------------------------------------------------------------------------- */

/*
 * Handle received GOSSIP (full message from an EAGER peer).
 *
 * If new: delivers to application, forwards to other EAGER peers,
 *         sends IHAVE to LAZY peers, caches for GRAFT.
 * If duplicate: sends PRUNE to sender.
 *
 * Returns true if message was new, false if duplicate.
 */
bool wake_plumtree_recv_gossip(
    wake_plumtree_t *pt,
    const uint8_t from_id[WAKE_PLUMTREE_NODE_ID_LEN],
    const wake_plumtree_msg_id_t *msg_id,
    const void *payload,
    uint32_t payload_len,
    uint64_t now_ms,
    wake_plumtree_send_fn send_fn,
    wake_plumtree_deliver_fn deliver_fn,
    void *ctx);

/*
 * Handle received IHAVE (lazy notification).
 *
 * If we already have the message: ignore.
 * If we don't: record as pending. tick() will GRAFT after timeout.
 */
void wake_plumtree_recv_ihave(
    wake_plumtree_t *pt,
    const uint8_t from_id[WAKE_PLUMTREE_NODE_ID_LEN],
    const wake_plumtree_msg_id_t *msg_id,
    uint64_t now_ms);

/*
 * Handle received GRAFT (repair request from a peer).
 *
 * Promotes the sender to EAGER. If the message is in cache,
 * sends GOSSIP back to the requester.
 */
void wake_plumtree_recv_graft(
    wake_plumtree_t *pt,
    const uint8_t from_id[WAKE_PLUMTREE_NODE_ID_LEN],
    const wake_plumtree_msg_id_t *msg_id,
    uint64_t now_ms,
    wake_plumtree_send_fn send_fn,
    void *ctx);

/*
 * Handle received PRUNE (demotion request).
 *
 * Moves the sender from EAGER to LAZY in our peer list.
 */
void wake_plumtree_recv_prune(
    wake_plumtree_t *pt,
    const uint8_t from_id[WAKE_PLUMTREE_NODE_ID_LEN],
    uint64_t now_ms);

/* --------------------------------------------------------------------------
 * Timer tick (called periodically by the host application)
 *
 * Checks pending IHAVEs for timeout → sends GRAFT.
 * Evicts expired cache entries.
 *
 * Returns the number of GRAFTs sent.
 * -------------------------------------------------------------------------- */

uint32_t wake_plumtree_tick(
    wake_plumtree_t *pt,
    uint64_t now_ms,
    wake_plumtree_send_fn send_fn,
    void *ctx);

/* --------------------------------------------------------------------------
 * Inspection and statistics
 * -------------------------------------------------------------------------- */

void wake_plumtree_stats(const wake_plumtree_t *pt,
                          wake_plumtree_stats_t *out);

/* Check if a message ID is in the cache. */
bool wake_plumtree_has_msg(const wake_plumtree_t *pt,
                            const wake_plumtree_msg_id_t *msg_id);

/* --------------------------------------------------------------------------
 * Name accessors
 * -------------------------------------------------------------------------- */

const char *wake_plumtree_link_name(wake_plumtree_link_t link);
const char *wake_plumtree_msg_type_name(wake_plumtree_msg_type_t type);
const char *wake_plumtree_result_name(wake_plumtree_result_t r);

#ifdef __cplusplus
}
#endif

#endif /* WAKE_PLUMTREE_H */
