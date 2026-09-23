/*
 * wake_entity.c: WAKE Entity Model Implementation
 *
 * Copyright (c) 2026 Advens. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "wake_entity.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

/* =========================================================================
 * SipHash-2-4 implementation
 *
 * Reference: Jean-Philippe Aumasson & Daniel J. Bernstein
 * "SipHash: a fast short-input PRF" (2012)
 *
 * 128-bit key, arbitrary-length message, 64-bit output.
 * DoS-resistant: unpredictable output without knowing the key.
 * ========================================================================= */

static uint8_t siphash_key[16];
static bool    siphash_initialized = false;

static inline uint64_t
rotl64(uint64_t x, int b)
{
    return (x << b) | (x >> (64 - b));
}

static inline uint64_t
load_le64(const uint8_t *p)
{
    uint64_t v;
    memcpy(&v, p, 8);
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    v = __builtin_bswap64(v);
#endif
    return v;
}

#define SIPROUND do {           \
    v0 += v1;                   \
    v1 = rotl64(v1, 13);       \
    v1 ^= v0;                  \
    v0 = rotl64(v0, 32);       \
    v2 += v3;                   \
    v3 = rotl64(v3, 16);       \
    v3 ^= v2;                  \
    v0 += v3;                   \
    v3 = rotl64(v3, 21);       \
    v3 ^= v0;                  \
    v2 += v1;                   \
    v1 = rotl64(v1, 17);       \
    v1 ^= v2;                  \
    v2 = rotl64(v2, 32);       \
} while (0)

static uint64_t
siphash_2_4(const uint8_t *data, size_t len, const uint8_t key[16])
{
    uint64_t k0 = load_le64(key);
    uint64_t k1 = load_le64(key + 8);

    uint64_t v0 = k0 ^ UINT64_C(0x736f6d6570736575);
    uint64_t v1 = k1 ^ UINT64_C(0x646f72616e646f6d);
    uint64_t v2 = k0 ^ UINT64_C(0x6c7967656e657261);
    uint64_t v3 = k1 ^ UINT64_C(0x7465646279746573);

    const uint8_t *end = data + (len & ~7ULL);
    const size_t left = len & 7;

    /* Process 8-byte blocks */
    for (const uint8_t *p = data; p < end; p += 8) {
        uint64_t m = load_le64(p);
        v3 ^= m;
        SIPROUND;
        SIPROUND;
        v0 ^= m;
    }

    /* Process remaining bytes + length encoding */
    uint64_t b = (uint64_t)len << 56;
    switch (left) {
    case 7: b |= (uint64_t)end[6] << 48; /* fallthrough */
    case 6: b |= (uint64_t)end[5] << 40; /* fallthrough */
    case 5: b |= (uint64_t)end[4] << 32; /* fallthrough */
    case 4: b |= (uint64_t)end[3] << 24; /* fallthrough */
    case 3: b |= (uint64_t)end[2] << 16; /* fallthrough */
    case 2: b |= (uint64_t)end[1] << 8;  /* fallthrough */
    case 1: b |= (uint64_t)end[0];       break;
    case 0: break;
    }

    v3 ^= b;
    SIPROUND;
    SIPROUND;
    v0 ^= b;

    /* Finalization */
    v2 ^= 0xff;
    SIPROUND;
    SIPROUND;
    SIPROUND;
    SIPROUND;

    return v0 ^ v1 ^ v2 ^ v3;
}

#undef SIPROUND

/* =========================================================================
 * Hash subsystem
 * ========================================================================= */

int
wake_hash_init(void)
{
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0)
        return -1;

    ssize_t n = read(fd, siphash_key, sizeof(siphash_key));
    close(fd);

    if (n != (ssize_t)sizeof(siphash_key))
        return -1;

    siphash_initialized = true;
    return 0;
}

void
wake_hash_set_key(const uint8_t key[16])
{
    memcpy(siphash_key, key, 16);
    siphash_initialized = true;
}

uint64_t
wake_hash_bytes_keyed(const void *data, size_t len, const uint8_t key[16])
{
    return siphash_2_4((const uint8_t *)data, len, key);
}

/* =========================================================================
 * Entity construction
 *
 * Every init function zeroes the struct first to guarantee deterministic
 * hashing (no uninitialized padding bytes).
 * ========================================================================= */

void
wake_entity_init_ipv4(wake_entity_t *e, wake_eclass_t ec, uint32_t addr_nbo)
{
    memset(e, 0, sizeof(*e));
    e->eclass    = (uint8_t)ec;
    e->etype     = WAKE_ET_IPV4;
    e->value_len = 4;
    memcpy(e->value, &addr_nbo, 4);
}

void
wake_entity_init_ipv6(wake_entity_t *e, wake_eclass_t ec,
                      const uint8_t addr[16])
{
    memset(e, 0, sizeof(*e));
    e->eclass    = (uint8_t)ec;
    e->etype     = WAKE_ET_IPV6;
    e->value_len = 16;
    memcpy(e->value, addr, 16);
}

void
wake_entity_init_str(wake_entity_t *e, wake_eclass_t ec,
                     wake_etype_t et, const char *val, size_t len)
{
    memset(e, 0, sizeof(*e));
    e->eclass = (uint8_t)ec;
    e->etype  = (uint8_t)et;

    if (len <= WAKE_ENTITY_VALUE_MAX) {
        e->value_len = (uint8_t)len;
        memcpy(e->value, val, len);
    } else {
        /*
         * Value exceeds inline capacity. Store a SipHash of the original
         * so the entity remains uniquely identifiable (with negligible
         * collision probability for 64-bit hash).
         */
        uint64_t h = siphash_2_4((const uint8_t *)val, len, siphash_key);
        e->value_len = 8;
        e->flags     = WAKE_EF_HASHED;
        memcpy(e->value, &h, 8);
    }
}

void
wake_entity_init_md5(wake_entity_t *e, const uint8_t hash[16])
{
    memset(e, 0, sizeof(*e));
    e->eclass    = (uint8_t)WAKE_EC_WITH;
    e->etype     = WAKE_ET_HASH_MD5;
    e->value_len = 16;
    memcpy(e->value, hash, 16);
}

void
wake_entity_init_sha1(wake_entity_t *e, const uint8_t hash[20])
{
    memset(e, 0, sizeof(*e));
    e->eclass    = (uint8_t)WAKE_EC_WITH;
    e->etype     = WAKE_ET_HASH_SHA1;
    e->value_len = 20;
    memcpy(e->value, hash, 20);
}

void
wake_entity_init_sha256(wake_entity_t *e, const uint8_t hash[32])
{
    memset(e, 0, sizeof(*e));
    e->eclass    = (uint8_t)WAKE_EC_WITH;
    e->etype     = WAKE_ET_HASH_SHA256;
    e->value_len = 32;
    memcpy(e->value, hash, 32);
}

void
wake_entity_init_port(wake_entity_t *e, wake_eclass_t ec, uint16_t port)
{
    memset(e, 0, sizeof(*e));
    e->eclass    = (uint8_t)ec;
    e->etype     = WAKE_ET_PORT;
    e->value_len = 2;
    memcpy(e->value, &port, 2);
}

void
wake_entity_init_proto(wake_entity_t *e, uint8_t iana_proto)
{
    memset(e, 0, sizeof(*e));
    e->eclass    = (uint8_t)WAKE_EC_WITH;
    e->etype     = WAKE_ET_PROTO;
    e->value_len = 1;
    e->value[0]  = iana_proto;
}

void
wake_entity_init_size(wake_entity_t *e, uint64_t bytes)
{
    memset(e, 0, sizeof(*e));
    e->eclass    = (uint8_t)WAKE_EC_WITH;
    e->etype     = WAKE_ET_SIZE;
    e->value_len = 8;
    memcpy(e->value, &bytes, 8);
}

void
wake_entity_init_sig_id(wake_entity_t *e, uint32_t sig_id)
{
    memset(e, 0, sizeof(*e));
    e->eclass    = (uint8_t)WAKE_EC_WITH;
    e->etype     = WAKE_ET_SIG_ID;
    e->value_len = 4;
    memcpy(e->value, &sig_id, 4);
}

/* =========================================================================
 * Entity operations
 * ========================================================================= */

uint64_t
wake_entity_hash(const wake_entity_t *e)
{
    /*
     * Hash the 8-byte header (class, type, length, flags, reserved) plus
     * value[0..value_len). value_len is inside the header, so two entities
     * with the same prefix but different lengths hash differently.
     */
    return siphash_2_4((const uint8_t *)e,
                       8 + (size_t)e->value_len,
                       siphash_key);
}

bool
wake_entity_eq(const wake_entity_t *a, const wake_entity_t *b)
{
    /*
     * Fast path: compare the entire 64-byte struct. Since unused value
     * bytes are guaranteed zero and reserved is guaranteed zero, this
     * is equivalent to comparing (eclass, etype, value_len, flags, value).
     */
    return memcmp(a, b, sizeof(wake_entity_t)) == 0;
}

bool
wake_entity_valid(const wake_entity_t *e)
{
    /* Class in range */
    if (e->eclass >= WAKE_EC__COUNT)
        return false;

    /* Value length within bounds */
    if (e->value_len > WAKE_ENTITY_VALUE_MAX)
        return false;

    /* Reserved field must be zero */
    if (e->reserved != 0)
        return false;

    /* Unused value bytes must be zero (deterministic hashing invariant) */
    for (size_t i = e->value_len; i < WAKE_ENTITY_VALUE_MAX; i++) {
        if (e->value[i] != 0)
            return false;
    }

    /* Fixed-size types must have exact length (unless hashed) */
    if (!(e->flags & WAKE_EF_HASHED)) {
        uint8_t expected = wake_etype_fixed_len((wake_etype_t)e->etype);
        if (expected > 0 && e->value_len != expected)
            return false;
    }

    return true;
}

/* --------------------------------------------------------------------------
 * Formatting helpers (static, internal)
 * -------------------------------------------------------------------------- */

static int
format_ipv4(const uint8_t *addr, char *buf, size_t bufsz)
{
    return snprintf(buf, bufsz, "%u.%u.%u.%u",
                    addr[0], addr[1], addr[2], addr[3]);
}

static int
format_ipv6(const uint8_t *addr, char *buf, size_t bufsz)
{
    char tmp[INET6_ADDRSTRLEN];
    if (inet_ntop(AF_INET6, addr, tmp, sizeof(tmp)) == NULL)
        return snprintf(buf, bufsz, "<invalid-ipv6>");
    return snprintf(buf, bufsz, "%s", tmp);
}

static int
format_hex(const uint8_t *data, size_t len, char *buf, size_t bufsz)
{
    static const char hex[] = "0123456789abcdef";
    size_t needed = len * 2 + 1;

    if (bufsz == 0)
        return (int)(needed - 1);

    size_t out = 0;
    for (size_t i = 0; i < len && out + 2 < bufsz; i++) {
        buf[out++] = hex[data[i] >> 4];
        buf[out++] = hex[data[i] & 0x0f];
    }
    buf[out] = '\0';
    return (int)out;
}

static int
format_string(const uint8_t *data, size_t len, char *buf, size_t bufsz)
{
    if (bufsz == 0)
        return (int)len;

    size_t n = len < bufsz - 1 ? len : bufsz - 1;
    memcpy(buf, data, n);
    buf[n] = '\0';
    return (int)n;
}

static int
format_uint16(const uint8_t *data, char *buf, size_t bufsz)
{
    uint16_t v;
    memcpy(&v, data, 2);
    return snprintf(buf, bufsz, "%u", v);
}

static int
format_uint32(const uint8_t *data, char *buf, size_t bufsz)
{
    uint32_t v;
    memcpy(&v, data, 4);
    return snprintf(buf, bufsz, "%u", v);
}

static int
format_uint64(const uint8_t *data, char *buf, size_t bufsz)
{
    uint64_t v;
    memcpy(&v, data, 8);
    return snprintf(buf, bufsz, "%llu", (unsigned long long)v);
}

/* --------------------------------------------------------------------------
 * Public formatting
 * -------------------------------------------------------------------------- */

int
wake_entity_format(const wake_entity_t *e, char *buf, size_t bufsz)
{
    if (bufsz == 0)
        return -1;

    const char *cls  = wake_eclass_name((wake_eclass_t)e->eclass);
    const char *type = wake_etype_name((wake_etype_t)e->etype);

    int off = snprintf(buf, bufsz, "%s:%s:", cls, type);
    if (off < 0 || (size_t)off >= bufsz) {
        buf[bufsz - 1] = '\0';
        return -1;
    }

    char *vbuf    = buf + off;
    size_t vbufsz = bufsz - (size_t)off;
    int vlen;

    if (e->flags & WAKE_EF_HASHED) {
        vlen = snprintf(vbuf, vbufsz, "H:");
        if (vlen > 0 && (size_t)vlen < vbufsz)
            vlen += format_hex(e->value, e->value_len,
                               vbuf + vlen, vbufsz - (size_t)vlen);
    } else {
        switch ((wake_etype_t)e->etype) {
        case WAKE_ET_IPV4:
            vlen = format_ipv4(e->value, vbuf, vbufsz);
            break;
        case WAKE_ET_IPV6:
            vlen = format_ipv6(e->value, vbuf, vbufsz);
            break;
        case WAKE_ET_USER:
        case WAKE_ET_MACHINE:
        case WAKE_ET_EMAIL:
        case WAKE_ET_DOMAIN:
        case WAKE_ET_SERVICE:
        case WAKE_ET_PATH:
        case WAKE_ET_URL:
            vlen = format_string(e->value, e->value_len, vbuf, vbufsz);
            break;
        case WAKE_ET_HASH_MD5:
        case WAKE_ET_HASH_SHA1:
        case WAKE_ET_HASH_SHA256:
            vlen = format_hex(e->value, e->value_len, vbuf, vbufsz);
            break;
        case WAKE_ET_PORT:
            vlen = format_uint16(e->value, vbuf, vbufsz);
            break;
        case WAKE_ET_PROTO:
            vlen = snprintf(vbuf, vbufsz, "%u", e->value[0]);
            break;
        case WAKE_ET_SIZE:
            vlen = format_uint64(e->value, vbuf, vbufsz);
            break;
        case WAKE_ET_SIG_ID:
            vlen = format_uint32(e->value, vbuf, vbufsz);
            break;
        default:
            vlen = format_hex(e->value, e->value_len, vbuf, vbufsz);
            break;
        }
    }

    if (vlen < 0)
        return -1;

    return off + vlen;
}

/* =========================================================================
 * Enum name accessors
 * ========================================================================= */

const char *
wake_eclass_name(wake_eclass_t ec)
{
    switch (ec) {
    case WAKE_EC_WHO:    return "WHO";
    case WAKE_EC_WHOM:   return "WHOM";
    case WAKE_EC_WITH:   return "WITH";
    default:             return "UNKNOWN_CLASS";
    }
}

const char *
wake_etype_name(wake_etype_t et)
{
    switch (et) {
    case WAKE_ET_IPV4:       return "IPV4";
    case WAKE_ET_IPV6:       return "IPV6";
    case WAKE_ET_USER:       return "USER";
    case WAKE_ET_MACHINE:    return "MACHINE";
    case WAKE_ET_EMAIL:      return "EMAIL";
    case WAKE_ET_DOMAIN:     return "DOMAIN";
    case WAKE_ET_SERVICE:    return "SERVICE";
    case WAKE_ET_PATH:       return "PATH";
    case WAKE_ET_URL:        return "URL";
    case WAKE_ET_HASH_MD5:   return "HASH_MD5";
    case WAKE_ET_HASH_SHA1:  return "HASH_SHA1";
    case WAKE_ET_HASH_SHA256:return "HASH_SHA256";
    case WAKE_ET_PORT:       return "PORT";
    case WAKE_ET_PROTO:      return "PROTO";
    case WAKE_ET_SIZE:       return "SIZE";
    case WAKE_ET_SIG_ID:     return "SIG_ID";
    default:                 return "UNKNOWN_TYPE";
    }
}

const char *
wake_action_name(wake_action_t a)
{
    switch (a) {
    case WAKE_ACTION_UNKNOWN: return "UNKNOWN";
    case WAKE_ACTION_AUTH:    return "AUTH";
    case WAKE_ACTION_NETWORK: return "NETWORK";
    case WAKE_ACTION_FILE:    return "FILE";
    case WAKE_ACTION_EXEC:    return "EXEC";
    case WAKE_ACTION_POLICY:  return "POLICY";
    case WAKE_ACTION_SYSTEM:  return "SYSTEM";
    case WAKE_ACTION_DNS:     return "DNS";
    case WAKE_ACTION_MAIL:    return "MAIL";
    case WAKE_ACTION_WEB:     return "WEB";
    default:                  return "UNKNOWN_ACTION";
    }
}

const char *
wake_outcome_name(wake_outcome_t o)
{
    switch (o) {
    case WAKE_OUTCOME_UNKNOWN: return "UNKNOWN";
    case WAKE_OUTCOME_SUCCESS: return "SUCCESS";
    case WAKE_OUTCOME_FAILURE: return "FAILURE";
    case WAKE_OUTCOME_ERROR:   return "ERROR";
    default:                   return "UNKNOWN_OUTCOME";
    }
}
