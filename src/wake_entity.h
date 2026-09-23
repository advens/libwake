/*
 * wake_entity.h: WAKE Entity Model
 *
 * The entity is the fundamental unit of observation in WAKE. It represents
 * a semantic element extracted from a log event: a source IP, a destination
 * service, a file hash, etc.
 *
 * Design inspired by the immune system's antigen model: entities are the
 * "antigens" that accumulate evidence. Actions and outcomes are context
 * recorded with each observation.
 *
 * The entity struct is exactly 64 bytes, aligned to 64. That is one
 * hardware cache line only where the line size is 64.
 *
 * Copyright (c) 2026 Advens. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef WAKE_ENTITY_H
#define WAKE_ENTITY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/* --------------------------------------------------------------------------
 * Entity value capacity
 *
 * 56 bytes covers: IPv4 (4), IPv6 (16), SHA-256 (32), usernames (POSIX
 * limit 32), most domains (<56 chars). Values exceeding this are hashed
 * with SipHash and stored with WAKE_EF_HASHED flag set.
 * -------------------------------------------------------------------------- */
#define WAKE_ENTITY_VALUE_MAX 56

/* --------------------------------------------------------------------------
 * Entity classes: the three semantic categories (the "senses")
 *
 * WHO:  source identity (where did this come from?)
 * WHOM: destination (where was this going?)
 * WITH: discriminants (what characteristics does it carry?)
 * -------------------------------------------------------------------------- */
typedef enum {
    WAKE_EC_WHO  = 0,  /* Source identity (IP, user, machine)       */
    WAKE_EC_WHOM = 1,  /* Destination (IP, service, path, domain)   */
    WAKE_EC_WITH = 2,  /* Discriminants (hash, port, proto, sig ID) */
    WAKE_EC__COUNT = 3
} wake_eclass_t;

/* --------------------------------------------------------------------------
 * Entity types: the specific data format within each class
 *
 * Types encode both the semantic meaning AND the binary layout of value[].
 * The first nibble groups types by class affinity (0x1x=address, 0x2x=identity,
 * 0x3x=service, 0x4x=hash, 0x5x=numeric, 0x6x=string).
 * -------------------------------------------------------------------------- */
typedef enum {
    /* Address types: value[] contains binary address */
    WAKE_ET_IPV4      = 0x10,  /* 4 bytes, network byte order              */
    WAKE_ET_IPV6      = 0x11,  /* 16 bytes, network byte order             */

    /* Identity types: value[] contains raw string bytes */
    WAKE_ET_USER      = 0x20,  /* Username (UTF-8, not null-terminated)     */
    WAKE_ET_MACHINE   = 0x21,  /* Hostname / machine name                  */
    WAKE_ET_EMAIL     = 0x22,  /* Email address                            */

    /* Service/path types: value[] contains raw string bytes */
    WAKE_ET_DOMAIN    = 0x30,  /* DNS domain name, stored as the caller passed it */
    WAKE_ET_SERVICE   = 0x31,  /* Service name or identifier               */
    WAKE_ET_PATH      = 0x32,  /* File path or URL path                    */
    WAKE_ET_URL       = 0x33,  /* Full URL                                 */

    /* Hash types: value[] contains binary hash (not hex string) */
    WAKE_ET_HASH_MD5    = 0x40,  /* 16 bytes                               */
    WAKE_ET_HASH_SHA1   = 0x41,  /* 20 bytes                               */
    WAKE_ET_HASH_SHA256 = 0x42,  /* 32 bytes                               */

    /* Numeric types: value[] contains little-endian integer */
    WAKE_ET_PORT      = 0x50,  /* 2 bytes, uint16_t LE                     */
    WAKE_ET_PROTO     = 0x51,  /* 1 byte, IANA protocol number             */
    WAKE_ET_SIZE      = 0x52,  /* 8 bytes, uint64_t LE                     */
    WAKE_ET_SIG_ID    = 0x53,  /* 4 bytes, uint32_t LE (IDS rule ID)       */
} wake_etype_t;

/* --------------------------------------------------------------------------
 * Action types: WHAT happened (log event classification)
 *
 * These are not entities: they are the context that weights a deposit.
 * A single log event has exactly one action type.
 * -------------------------------------------------------------------------- */
typedef enum {
    WAKE_ACTION_UNKNOWN  = 0,
    WAKE_ACTION_AUTH     = 1,   /* Authentication (login, logout, MFA)      */
    WAKE_ACTION_NETWORK  = 2,   /* Network connection / session / flow      */
    WAKE_ACTION_FILE     = 3,   /* File operation (CRUD)                    */
    WAKE_ACTION_EXEC     = 4,   /* Process / command execution              */
    WAKE_ACTION_POLICY   = 5,   /* Policy, rule, or config change           */
    WAKE_ACTION_SYSTEM   = 6,   /* System lifecycle (service, resource)     */
    WAKE_ACTION_DNS      = 7,   /* DNS query / response                     */
    WAKE_ACTION_MAIL     = 8,   /* Email event                              */
    WAKE_ACTION_WEB      = 9,   /* HTTP / web request                       */
    WAKE_ACTION__COUNT   = 10
} wake_action_t;

/* --------------------------------------------------------------------------
 * Outcome types: HOW it ended (event result classification)
 * -------------------------------------------------------------------------- */
typedef enum {
    WAKE_OUTCOME_UNKNOWN = 0,
    WAKE_OUTCOME_SUCCESS = 1,   /* Succeeded / allowed / accepted           */
    WAKE_OUTCOME_FAILURE = 2,   /* Failed / denied / blocked / rejected     */
    WAKE_OUTCOME_ERROR   = 3,   /* Internal error / timeout                 */
    WAKE_OUTCOME__COUNT  = 4
} wake_outcome_t;

/* --------------------------------------------------------------------------
 * Entity flags
 * -------------------------------------------------------------------------- */
#define WAKE_EF_NONE     0x00
#define WAKE_EF_HASHED   0x01   /* value[] contains SipHash of original
                                   (original was > WAKE_ENTITY_VALUE_MAX)  */

/* --------------------------------------------------------------------------
 * Entity struct: 64 bytes, aligned to 64
 *
 * Layout (all offsets in bytes):
 *   [0]     eclass     Entity class (WHO/WHOM/WITH)
 *   [1]     etype      Entity type (IPV4/USER/HASH_SHA256/...)
 *   [2]     value_len  Actual byte length of value (0..56)
 *   [3]     flags      WAKE_EF_* flags
 *   [4..7]  reserved   Must be 0 (ABI stability)
 *   [8..63] value      Entity value, zero-padded to 56 bytes
 *
 * INVARIANTS:
 *   - value_len <= WAKE_ENTITY_VALUE_MAX
 *   - value[value_len .. WAKE_ENTITY_VALUE_MAX-1] == 0 (deterministic hash)
 *   - reserved == 0
 *   - eclass < WAKE_EC__COUNT
 * -------------------------------------------------------------------------- */
typedef struct {
    uint8_t  eclass;
    uint8_t  etype;
    uint8_t  value_len;
    uint8_t  flags;
    uint32_t reserved;
    uint8_t  value[WAKE_ENTITY_VALUE_MAX];
} __attribute__((aligned(64))) wake_entity_t;

_Static_assert(sizeof(wake_entity_t) == 64,
    "wake_entity_t must be exactly 64 bytes");

/* --------------------------------------------------------------------------
 * Hash subsystem initialization
 *
 * Reads 16 bytes from /dev/urandom. wake_hash_set_key() is the other
 * initializer (pheromone create/open). Call either one before
 * wake_entity_hash() or before hashing an over-long string.
 *
 * Returns 0 on success, -1 on failure (unable to read random bytes).
 * -------------------------------------------------------------------------- */
int wake_hash_init(void);

/* Install a 16-byte SipHash key and mark the key initialized. */
void wake_hash_set_key(const uint8_t key[16]);

/* Raw-bytes SipHash-2-4 with an explicit key. Does not touch the process-global
 * key or wake_hash_init() state. Used by callers that own their own key
 * (e.g. wake_tac). */
uint64_t wake_hash_bytes_keyed(const void *data, size_t len,
                               const uint8_t key[16]);

/* --------------------------------------------------------------------------
 * Entity construction
 *
 * All init functions zero the entire struct first, then set fields.
 * This guarantees deterministic hashing (no uninitialized padding bytes).
 *
 * String init functions (user, machine, email, domain, service, path, url)
 * handle values longer than WAKE_ENTITY_VALUE_MAX by hashing them and
 * setting WAKE_EF_HASHED. The len parameter is the byte length of the
 * value (not including any null terminator).
 * -------------------------------------------------------------------------- */

/* Address entities */
void wake_entity_init_ipv4(wake_entity_t *e, wake_eclass_t ec,
                           uint32_t addr_nbo);
void wake_entity_init_ipv6(wake_entity_t *e, wake_eclass_t ec,
                           const uint8_t addr[16]);

/* String entities (auto-hashed if too long) */
void wake_entity_init_str(wake_entity_t *e, wake_eclass_t ec,
                          wake_etype_t et, const char *val, size_t len);

/* Convenience wrappers for common string entities */
static inline void
wake_entity_init_user(wake_entity_t *e, wake_eclass_t ec,
                      const char *val, size_t len)
{
    wake_entity_init_str(e, ec, WAKE_ET_USER, val, len);
}

static inline void
wake_entity_init_machine(wake_entity_t *e, wake_eclass_t ec,
                         const char *val, size_t len)
{
    wake_entity_init_str(e, ec, WAKE_ET_MACHINE, val, len);
}

static inline void
wake_entity_init_email(wake_entity_t *e, wake_eclass_t ec,
                       const char *val, size_t len)
{
    wake_entity_init_str(e, ec, WAKE_ET_EMAIL, val, len);
}

static inline void
wake_entity_init_domain(wake_entity_t *e, wake_eclass_t ec,
                        const char *val, size_t len)
{
    wake_entity_init_str(e, ec, WAKE_ET_DOMAIN, val, len);
}

static inline void
wake_entity_init_service(wake_entity_t *e, wake_eclass_t ec,
                         const char *val, size_t len)
{
    wake_entity_init_str(e, ec, WAKE_ET_SERVICE, val, len);
}

static inline void
wake_entity_init_path(wake_entity_t *e, wake_eclass_t ec,
                      const char *val, size_t len)
{
    wake_entity_init_str(e, ec, WAKE_ET_PATH, val, len);
}

static inline void
wake_entity_init_url(wake_entity_t *e, wake_eclass_t ec,
                     const char *val, size_t len)
{
    wake_entity_init_str(e, ec, WAKE_ET_URL, val, len);
}

/* Hash entities (binary, fixed-size) */
void wake_entity_init_md5(wake_entity_t *e, const uint8_t hash[16]);
void wake_entity_init_sha1(wake_entity_t *e, const uint8_t hash[20]);
void wake_entity_init_sha256(wake_entity_t *e, const uint8_t hash[32]);

/* Numeric entities */
void wake_entity_init_port(wake_entity_t *e, wake_eclass_t ec, uint16_t port);
void wake_entity_init_proto(wake_entity_t *e, uint8_t iana_proto);
void wake_entity_init_size(wake_entity_t *e, uint64_t bytes);
void wake_entity_init_sig_id(wake_entity_t *e, uint32_t sig_id);

/* --------------------------------------------------------------------------
 * Entity operations
 * -------------------------------------------------------------------------- */

/* Hash entity for use as table key. Requires wake_hash_init() or
 * wake_hash_set_key() first. */
uint64_t wake_entity_hash(const wake_entity_t *e);

/* Compare two entities for equality (class + type + value). */
bool wake_entity_eq(const wake_entity_t *a, const wake_entity_t *b);

/* Validate entity invariants. Returns true if all invariants hold. */
bool wake_entity_valid(const wake_entity_t *e);

/*
 * Format entity as human-readable string.
 * Returns number of bytes written (excluding NUL), or -1 on error.
 * Output is always NUL-terminated if bufsz > 0.
 *
 * Format: "CLASS:TYPE:VALUE" e.g. "WHO:IPV4:192.168.1.1"
 */
int wake_entity_format(const wake_entity_t *e, char *buf, size_t bufsz);

/* --------------------------------------------------------------------------
 * Name accessors for enums (return static strings, never NULL)
 * -------------------------------------------------------------------------- */
const char *wake_eclass_name(wake_eclass_t ec);
const char *wake_etype_name(wake_etype_t et);
const char *wake_action_name(wake_action_t a);
const char *wake_outcome_name(wake_outcome_t o);

/* --------------------------------------------------------------------------
 * Type introspection helpers
 * -------------------------------------------------------------------------- */

/* Expected value_len for fixed-size types. Returns 0 for variable-length. */
static inline uint8_t
wake_etype_fixed_len(wake_etype_t et)
{
    switch (et) {
    case WAKE_ET_IPV4:       return 4;
    case WAKE_ET_IPV6:       return 16;
    case WAKE_ET_HASH_MD5:   return 16;
    case WAKE_ET_HASH_SHA1:  return 20;
    case WAKE_ET_HASH_SHA256:return 32;
    case WAKE_ET_PORT:       return 2;
    case WAKE_ET_PROTO:      return 1;
    case WAKE_ET_SIZE:       return 8;
    case WAKE_ET_SIG_ID:     return 4;
    default:                 return 0;
    }
}

/* True if entity type carries a variable-length string value. */
static inline bool
wake_etype_is_string(wake_etype_t et)
{
    return (et & 0xF0) == 0x20  /* identity types */
        || (et & 0xF0) == 0x30; /* service/path types */
}

/* True if entity type carries a binary address. */
static inline bool
wake_etype_is_addr(wake_etype_t et)
{
    return (et & 0xF0) == 0x10;
}

/* True if entity type carries a cryptographic hash. */
static inline bool
wake_etype_is_hash(wake_etype_t et)
{
    return (et & 0xF0) == 0x40;
}

/* True if entity type carries a numeric value. */
static inline bool
wake_etype_is_numeric(wake_etype_t et)
{
    return (et & 0xF0) == 0x50;
}

#ifdef __cplusplus
}
#endif

#endif /* WAKE_ENTITY_H */
