/*
 * wake_signal.h: WAKE Mesh Signal Format
 *
 * A signal is the fundamental unit of inter-node communication in WAKE.
 * It carries an entity observation from one node to another, signed with
 * Ed25519 for tamper detection and attribution.
 *
 * Bio-inspiration: pheromone trail deposit. When a node observes a
 * suspicious entity, it emits a signal that propagates through the mesh,
 * reinforcing pheromone tables at each hop.
 *
 * Wire format: fixed-size binary struct (192 bytes, three 64-byte groups).
 * The wire image is the struct itself; there is no separate text encoding.
 *
 * Memory layout:
 *   [0..63]    entity: the entity being signaled
 *   [64..127]  metadata: signal context
 *   [128..191] signature: Ed25519 signature over [0..127]
 *
 * Scope model (quorum sensing):
 *   TENANT: signal stays within one tenant
 *   FLEET: signal propagates across tenants
 *
 * Copyright (c) 2026 Advens. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef WAKE_SIGNAL_H
#define WAKE_SIGNAL_H

#include "wake_crypto.h"
#include "wake_entity.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* --------------------------------------------------------------------------
 * Signal type: what kind of observation is this?
 * -------------------------------------------------------------------------- */
typedef enum {
    WAKE_SIG_OBSERVATION = 0,  /* New local observation (deposit)           */
    WAKE_SIG_REINFORCE   = 1,  /* Remote reinforcement from another node    */
    WAKE_SIG_ALERT       = 2,  /* Quorum threshold reached                  */
    WAKE_SIG_RETRACT     = 3,  /* Entity cleared / false positive retracted */
    WAKE_SIG__COUNT      = 4
} wake_signal_type_t;

/* --------------------------------------------------------------------------
 * Signal scope: quorum sensing analog
 * -------------------------------------------------------------------------- */
typedef enum {
    WAKE_SCOPE_TENANT = 0,  /* tenant-local signal         */
    WAKE_SCOPE_FLEET  = 1,  /* fleet-wide broadcast        */
    WAKE_SCOPE__COUNT = 2
} wake_signal_scope_t;

/* --------------------------------------------------------------------------
 * Wire format version
 * -------------------------------------------------------------------------- */
#define WAKE_SIGNAL_VERSION   1
#define WAKE_SIGNAL_MAGIC     UINT16_C(0x574B)  /* on-wire bytes 0x4B, 0x57 when this uint16 is stored little-endian */

/* --------------------------------------------------------------------------
 * Signal metadata: 64 bytes (bytes 64..127 of the signal).
 *
 * All fields little-endian. 64 bytes is one hardware cache line only
 * where the line size is 64.
 * -------------------------------------------------------------------------- */
typedef struct {
    uint16_t magic;          /*  2B: WAKE_SIGNAL_MAGIC for framing     */
    uint8_t  version;        /*  1B: wire format version               */
    uint8_t  signal_type;    /*  1B: wake_signal_type_t                */
    uint8_t  scope;          /*  1B: wake_signal_scope_t               */
    uint8_t  ttl;            /*  1B: remaining hops (decremented)      */
    uint8_t  hop_count;      /*  1B: hops so far (incremented)         */
    uint8_t  action;         /*  1B: wake_action_t context             */
    uint8_t  outcome;        /*  1B: wake_outcome_t context            */
    uint8_t  _pad0[3];       /*  3B: pad                               */
    uint32_t phase_flags;    /*  4B: behavioral phase bitmask (OR'd)   */
    uint32_t tenant_id;      /*  4B: tenant isolation key              */
    uint32_t timestamp;      /*  4B: Unix epoch seconds                */
    uint32_t confidence;     /*  4B: confidence at emission            */
    uint32_t hit_count;      /*  4B: observation count at emission     */
    uint8_t  node_id[32];    /* 32B: emitter's Ed25519 public key      */
} wake_signal_meta_t;

_Static_assert(sizeof(wake_signal_meta_t) == 64,
    "signal metadata must be exactly 64 bytes");

/* --------------------------------------------------------------------------
 * Complete signal: 192 bytes (three 64-byte groups)
 *
 * Layout:
 *   [0..63]    entity (signed)
 *   [64..127]  metadata (signed)
 *   [128..191] Ed25519 signature over bytes [0..127]
 * -------------------------------------------------------------------------- */
typedef struct {
    wake_entity_t      entity;     /* 64B: the entity being signaled      */
    wake_signal_meta_t meta;       /* 64B: signal context                 */
    uint8_t            sig[64];    /* 64B: Ed25519 signature              */
} __attribute__((aligned(64))) wake_signal_t;

_Static_assert(sizeof(wake_signal_t) == 192,
    "signal must be exactly 192 bytes");

/* --------------------------------------------------------------------------
 * Signal construction
 * -------------------------------------------------------------------------- */

/*
 * Initialize a signal with the given parameters and sign it.
 *
 * The caller fills in the entity, metadata fields, and the function
 * stamps magic/version, sets node_id from the key, and signs the
 * first 128 bytes (entity + metadata).
 */
void wake_signal_init(wake_signal_t *sig,
                       const wake_entity_t *entity,
                       wake_signal_type_t signal_type,
                       wake_signal_scope_t scope,
                       wake_action_t action,
                       wake_outcome_t outcome,
                       uint32_t tenant_id,
                       uint32_t confidence,
                       uint32_t hit_count,
                       uint8_t ttl,
                       uint32_t phase_flags,
                       const wake_node_key_t *key);

/* --------------------------------------------------------------------------
 * Signal verification
 * -------------------------------------------------------------------------- */

/*
 * Verify signal integrity:
 *   1. Magic and version check
 *   2. Entity validity
 *   3. Ed25519 signature over bytes [0..127]
 *
 * Returns true if all checks pass.
 */
bool wake_signal_verify(const wake_signal_t *sig);

/* --------------------------------------------------------------------------
 * Signal forwarding (hop processing)
 * -------------------------------------------------------------------------- */

/*
 * Prepare a received signal for forwarding:
 *   - Decrements ttl
 *   - Increments hop_count
 *   - Re-signs with the forwarder's key (the forwarding node
 *     becomes the new emitter; chain of trust is one-hop)
 *
 * Returns false if ttl has reached 0 (should not forward).
 */
bool wake_signal_forward(wake_signal_t *sig, const wake_node_key_t *key);

/* --------------------------------------------------------------------------
 * Name accessors
 * -------------------------------------------------------------------------- */

const char *wake_signal_type_name(wake_signal_type_t t);
const char *wake_signal_scope_name(wake_signal_scope_t s);

#ifdef __cplusplus
}
#endif

#endif /* WAKE_SIGNAL_H */
