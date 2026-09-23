/*
 * wake_signal.c: WAKE Mesh Signal Implementation
 *
 * Copyright (c) 2026 Advens. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "wake_signal.h"

#include <string.h>
#include <time.h>

/* =========================================================================
 * Signal construction
 * ========================================================================= */

void
wake_signal_init(wake_signal_t *sig,
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
                  const wake_node_key_t *key)
{
    memset(sig, 0, sizeof(*sig));

    /* Entity (cache line 0) */
    memcpy(&sig->entity, entity, sizeof(wake_entity_t));

    /* Metadata (cache line 1) */
    sig->meta.magic       = WAKE_SIGNAL_MAGIC;
    sig->meta.version     = WAKE_SIGNAL_VERSION;
    sig->meta.signal_type = (uint8_t)signal_type;
    sig->meta.scope       = (uint8_t)scope;
    sig->meta.ttl         = ttl;
    sig->meta.hop_count   = 0;
    sig->meta.action      = (uint8_t)action;
    sig->meta.outcome     = (uint8_t)outcome;
    sig->meta.phase_flags = phase_flags;
    sig->meta.tenant_id   = tenant_id;
    sig->meta.confidence  = confidence;
    sig->meta.hit_count   = hit_count;

    /* Timestamp: Unix epoch seconds */
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    sig->meta.timestamp = (uint32_t)ts.tv_sec;

    /* Node identity = emitter's public key */
    memcpy(sig->meta.node_id, key->public_key, 32);

    /* Sign bytes [0..127] (entity + metadata) */
    wake_ed25519_sign(sig->sig,
                       (const void *)sig, 128,
                       key);
}

/* =========================================================================
 * Signal verification
 * ========================================================================= */

bool
wake_signal_verify(const wake_signal_t *sig)
{
    /* Framing check */
    if (sig->meta.magic != WAKE_SIGNAL_MAGIC)
        return false;

    if (sig->meta.version != WAKE_SIGNAL_VERSION)
        return false;

    /* Type range check */
    if (sig->meta.signal_type >= WAKE_SIG__COUNT)
        return false;

    if (sig->meta.scope >= WAKE_SCOPE__COUNT)
        return false;

    /* Entity validity */
    if (!wake_entity_valid(&sig->entity))
        return false;

    /* Ed25519 signature verification over bytes [0..127] */
    if (wake_ed25519_verify(sig->sig,
                             (const void *)sig, 128,
                             sig->meta.node_id) != 0) {
        return false;
    }

    return true;
}

/* =========================================================================
 * Signal forwarding
 * ========================================================================= */

bool
wake_signal_forward(wake_signal_t *sig, const wake_node_key_t *key)
{
    if (sig->meta.ttl == 0)
        return false;

    sig->meta.ttl--;
    sig->meta.hop_count++;

    /* Forwarder becomes new emitter */
    memcpy(sig->meta.node_id, key->public_key, 32);

    /* Re-sign with forwarder's key */
    wake_ed25519_sign(sig->sig,
                       (const void *)sig, 128,
                       key);

    return true;
}

/* =========================================================================
 * Name accessors
 * ========================================================================= */

const char *
wake_signal_type_name(wake_signal_type_t t)
{
    switch (t) {
    case WAKE_SIG_OBSERVATION: return "OBSERVATION";
    case WAKE_SIG_REINFORCE:   return "REINFORCE";
    case WAKE_SIG_ALERT:       return "ALERT";
    case WAKE_SIG_RETRACT:     return "RETRACT";
    default:                   return "UNKNOWN_SIGNAL_TYPE";
    }
}

const char *
wake_signal_scope_name(wake_signal_scope_t s)
{
    switch (s) {
    case WAKE_SCOPE_TENANT: return "TENANT";
    case WAKE_SCOPE_FLEET:  return "FLEET";
    default:                return "UNKNOWN_SCOPE";
    }
}
