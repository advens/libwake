/*
 * test_entity.c: wake_entity construction, hashing and formatting tests
 *
 * Copyright (c) 2026 Advens. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "wake_entity.h"

#include <stdio.h>
#include <string.h>

static int g_fail;

#define CHECK(cond)                                                          \
    do {                                                                     \
        if (!(cond)) {                                                       \
            printf("  FAIL %s:%d  %s\n", __func__, __LINE__, #cond);         \
            g_fail = 1;                                                      \
            return 1;                                                       \
        }                                                                     \
    } while (0)

static void set_key(void) {
    static const uint8_t key[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    wake_hash_set_key(key);
}

/* -------------------------------------------------------------------------- */
/* Construction                                                               */
/* -------------------------------------------------------------------------- */

static int test_ipv4_roundtrip(void) {
    wake_entity_t e;
    uint32_t addr = 0x0100007fu; /* already network-order bytes: 127.0.0.1 */
    wake_entity_init_ipv4(&e, WAKE_EC_WHO, addr);
    CHECK(e.eclass == WAKE_EC_WHO);
    CHECK(e.etype == WAKE_ET_IPV4);
    CHECK(e.value_len == 4);
    CHECK(e.flags == 0);
    CHECK(e.reserved == 0);
    CHECK(memcmp(e.value, &addr, 4) == 0);
    CHECK(wake_entity_valid(&e));

    char buf[64];
    int n = wake_entity_format(&e, buf, sizeof(buf));
    CHECK(n > 0);
    CHECK(strcmp(buf, "WHO:IPV4:127.0.0.1") == 0);
    return 0;
}

static int test_ipv6_roundtrip(void) {
    wake_entity_t e;
    uint8_t addr[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    wake_entity_init_ipv6(&e, WAKE_EC_WHOM, addr);
    CHECK(e.etype == WAKE_ET_IPV6);
    CHECK(e.value_len == 16);
    CHECK(wake_entity_valid(&e));

    char buf[64];
    CHECK(wake_entity_format(&e, buf, sizeof(buf)) > 0);
    CHECK(strcmp(buf, "WHOM:IPV6:2001:db8::1") == 0);
    return 0;
}

static int test_str_short_fits_inline(void) {
    wake_entity_t e;
    const char *user = "root";
    wake_entity_init_user(&e, WAKE_EC_WHO, user, strlen(user));
    CHECK(e.etype == WAKE_ET_USER);
    CHECK(e.value_len == strlen(user));
    CHECK((e.flags & WAKE_EF_HASHED) == 0);
    CHECK(memcmp(e.value, user, strlen(user)) == 0);
    CHECK(wake_entity_valid(&e));

    char buf[64];
    CHECK(wake_entity_format(&e, buf, sizeof(buf)) > 0);
    CHECK(strcmp(buf, "WHO:USER:root") == 0);
    return 0;
}

static int test_str_exactly_at_capacity(void) {
    wake_entity_t e;
    char val[WAKE_ENTITY_VALUE_MAX];
    memset(val, 'a', sizeof(val));
    wake_entity_init_machine(&e, WAKE_EC_WHO, val, sizeof(val));
    CHECK(e.value_len == WAKE_ENTITY_VALUE_MAX);
    CHECK((e.flags & WAKE_EF_HASHED) == 0);
    CHECK(wake_entity_valid(&e));
    return 0;
}

static int test_str_over_capacity_is_hashed(void) {
    set_key();
    wake_entity_t e;
    char val[WAKE_ENTITY_VALUE_MAX + 1];
    memset(val, 'b', sizeof(val));
    wake_entity_init_domain(&e, WAKE_EC_WHOM, val, sizeof(val));
    CHECK(e.value_len == 8);
    CHECK(e.flags & WAKE_EF_HASHED);
    CHECK(wake_entity_valid(&e));

    /* Same over-long value hashes to the same 8 bytes every time. */
    wake_entity_t e2;
    wake_entity_init_domain(&e2, WAKE_EC_WHOM, val, sizeof(val));
    CHECK(memcmp(e.value, e2.value, 8) == 0);

    /* A different over-long value hashes differently. */
    val[0] = 'c';
    wake_entity_t e3;
    wake_entity_init_domain(&e3, WAKE_EC_WHOM, val, sizeof(val));
    CHECK(memcmp(e.value, e3.value, 8) != 0);
    return 0;
}

static int test_hash_fixed_size_entities(void) {
    wake_entity_t md5, sha1, sha256;
    uint8_t h16[16], h20[20], h32[32];
    memset(h16, 0xaa, 16);
    memset(h20, 0xbb, 20);
    memset(h32, 0xcc, 32);

    wake_entity_init_md5(&md5, h16);
    CHECK(md5.eclass == WAKE_EC_WITH && md5.etype == WAKE_ET_HASH_MD5 && md5.value_len == 16);
    CHECK(wake_entity_valid(&md5));

    wake_entity_init_sha1(&sha1, h20);
    CHECK(sha1.etype == WAKE_ET_HASH_SHA1 && sha1.value_len == 20);
    CHECK(wake_entity_valid(&sha1));

    wake_entity_init_sha256(&sha256, h32);
    CHECK(sha256.etype == WAKE_ET_HASH_SHA256 && sha256.value_len == 32);
    CHECK(wake_entity_valid(&sha256));

    char buf[80];
    CHECK(wake_entity_format(&md5, buf, sizeof(buf)) > 0);
    CHECK(strcmp(buf, "WITH:HASH_MD5:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") == 0);
    return 0;
}

static int test_numeric_entities(void) {
    wake_entity_t port, proto, size, sig;

    wake_entity_init_port(&port, WAKE_EC_WITH, 8080);
    CHECK(port.etype == WAKE_ET_PORT && port.value_len == 2);
    char buf[32];
    CHECK(wake_entity_format(&port, buf, sizeof(buf)) > 0);
    CHECK(strcmp(buf, "WITH:PORT:8080") == 0);

    wake_entity_init_proto(&proto, 6 /* TCP */);
    CHECK(proto.etype == WAKE_ET_PROTO && proto.value_len == 1);
    CHECK(wake_entity_format(&proto, buf, sizeof(buf)) > 0);
    CHECK(strcmp(buf, "WITH:PROTO:6") == 0);

    wake_entity_init_size(&size, 1234567890123ULL);
    CHECK(size.etype == WAKE_ET_SIZE && size.value_len == 8);
    CHECK(wake_entity_format(&size, buf, sizeof(buf)) > 0);
    CHECK(strcmp(buf, "WITH:SIZE:1234567890123") == 0);

    wake_entity_init_sig_id(&sig, 42);
    CHECK(sig.etype == WAKE_ET_SIG_ID && sig.value_len == 4);
    CHECK(wake_entity_format(&sig, buf, sizeof(buf)) > 0);
    CHECK(strcmp(buf, "WITH:SIG_ID:42") == 0);
    return 0;
}

/* -------------------------------------------------------------------------- */
/* Equality, validity, deterministic padding                                 */
/* -------------------------------------------------------------------------- */

static int test_eq_and_padding_is_deterministic(void) {
    wake_entity_t a, b;
    wake_entity_init_user(&a, WAKE_EC_WHO, "alice", 5);
    wake_entity_init_user(&b, WAKE_EC_WHO, "alice", 5);
    CHECK(wake_entity_eq(&a, &b));

    /* Unused value bytes must be zero: two entities built the same way are
     * byte-identical, not just "equal by the fields that matter". */
    CHECK(memcmp(&a, &b, sizeof(a)) == 0);

    wake_entity_t c;
    wake_entity_init_user(&c, WAKE_EC_WHO, "alicX", 5);
    CHECK(!wake_entity_eq(&a, &c));

    wake_entity_t d;
    wake_entity_init_user(&d, WAKE_EC_WHOM, "alice", 5);
    CHECK(!wake_entity_eq(&a, &d)); /* same value, different class */
    return 0;
}

static int test_valid_rejects_corrupt_entities(void) {
    wake_entity_t e;
    wake_entity_init_user(&e, WAKE_EC_WHO, "bob", 3);
    CHECK(wake_entity_valid(&e));

    wake_entity_t bad_class = e;
    bad_class.eclass = WAKE_EC__COUNT;
    CHECK(!wake_entity_valid(&bad_class));

    wake_entity_t bad_len = e;
    bad_len.value_len = WAKE_ENTITY_VALUE_MAX + 1;
    CHECK(!wake_entity_valid(&bad_len));

    wake_entity_t bad_reserved = e;
    bad_reserved.reserved = 1;
    CHECK(!wake_entity_valid(&bad_reserved));

    wake_entity_t bad_padding = e;
    bad_padding.value[10] = 0xff; /* past value_len=3, must be zero */
    CHECK(!wake_entity_valid(&bad_padding));

    wake_entity_t bad_fixed_len = e;
    bad_fixed_len.etype = WAKE_ET_IPV4; /* claims 4 bytes, value_len is 3 */
    CHECK(!wake_entity_valid(&bad_fixed_len));
    return 0;
}

/* -------------------------------------------------------------------------- */
/* Hashing                                                                    */
/* -------------------------------------------------------------------------- */

static int test_hash_deterministic_and_key_dependent(void) {
    set_key();
    wake_entity_t e;
    wake_entity_init_ipv4(&e, WAKE_EC_WHO, 0x0100007fu);

    uint64_t h1 = wake_entity_hash(&e);
    uint64_t h2 = wake_entity_hash(&e);
    CHECK(h1 == h2);
    CHECK(h1 != 0); /* not a proof, but a zero hash would be a strong hint of a bug */

    /* A different value_len changes the hash even with the same class/type
     * and an identical value prefix (value_len is inside the hashed header,
     * ahead of value[], so it takes part in the hash before the prefix does). */
    wake_entity_t prefix, extended;
    wake_entity_init_user(&prefix, WAKE_EC_WHO, "ab", 2);
    wake_entity_init_user(&extended, WAKE_EC_WHO, "abc", 3);
    CHECK(wake_entity_hash(&prefix) != wake_entity_hash(&extended));

    /* Changing the SipHash key changes the hash of the same entity. */
    static const uint8_t other_key[16] = {16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1};
    wake_hash_set_key(other_key);
    uint64_t h4 = wake_entity_hash(&e);
    CHECK(h4 != h1);
    set_key(); /* restore for any test that runs after this one */
    return 0;
}

static int test_hash_bytes_keyed_independent_of_global_key(void) {
    static const uint8_t key_a[16] = {0xaa};
    static const uint8_t key_b[16] = {0xbb};
    const char *data = "fixed input";

    wake_hash_set_key(key_a);
    uint64_t with_a = wake_hash_bytes_keyed(data, strlen(data), key_b);

    wake_hash_set_key(key_b);
    uint64_t with_b_again = wake_hash_bytes_keyed(data, strlen(data), key_b);

    /* wake_hash_bytes_keyed ignores the process-global key entirely: both
     * calls used key_b explicitly and must agree regardless of what
     * wake_hash_set_key() did in between. */
    CHECK(with_a == with_b_again);
    set_key();
    return 0;
}

/* -------------------------------------------------------------------------- */
/* Type introspection and name accessors                                     */
/* -------------------------------------------------------------------------- */

static int test_etype_fixed_len(void) {
    CHECK(wake_etype_fixed_len(WAKE_ET_IPV4) == 4);
    CHECK(wake_etype_fixed_len(WAKE_ET_IPV6) == 16);
    CHECK(wake_etype_fixed_len(WAKE_ET_HASH_MD5) == 16);
    CHECK(wake_etype_fixed_len(WAKE_ET_HASH_SHA1) == 20);
    CHECK(wake_etype_fixed_len(WAKE_ET_HASH_SHA256) == 32);
    CHECK(wake_etype_fixed_len(WAKE_ET_PORT) == 2);
    CHECK(wake_etype_fixed_len(WAKE_ET_PROTO) == 1);
    CHECK(wake_etype_fixed_len(WAKE_ET_SIZE) == 8);
    CHECK(wake_etype_fixed_len(WAKE_ET_SIG_ID) == 4);
    CHECK(wake_etype_fixed_len(WAKE_ET_USER) == 0); /* variable-length */
    return 0;
}

static int test_etype_class_predicates(void) {
    CHECK(wake_etype_is_addr(WAKE_ET_IPV4));
    CHECK(wake_etype_is_addr(WAKE_ET_IPV6));
    CHECK(!wake_etype_is_addr(WAKE_ET_USER));

    CHECK(wake_etype_is_string(WAKE_ET_USER));
    CHECK(wake_etype_is_string(WAKE_ET_MACHINE));
    CHECK(wake_etype_is_string(WAKE_ET_EMAIL));
    CHECK(wake_etype_is_string(WAKE_ET_DOMAIN));
    CHECK(wake_etype_is_string(WAKE_ET_SERVICE));
    CHECK(wake_etype_is_string(WAKE_ET_PATH));
    CHECK(wake_etype_is_string(WAKE_ET_URL));
    CHECK(!wake_etype_is_string(WAKE_ET_IPV4));

    CHECK(wake_etype_is_hash(WAKE_ET_HASH_MD5));
    CHECK(wake_etype_is_hash(WAKE_ET_HASH_SHA1));
    CHECK(wake_etype_is_hash(WAKE_ET_HASH_SHA256));
    CHECK(!wake_etype_is_hash(WAKE_ET_PORT));

    CHECK(wake_etype_is_numeric(WAKE_ET_PORT));
    CHECK(wake_etype_is_numeric(WAKE_ET_PROTO));
    CHECK(wake_etype_is_numeric(WAKE_ET_SIZE));
    CHECK(wake_etype_is_numeric(WAKE_ET_SIG_ID));
    CHECK(!wake_etype_is_numeric(WAKE_ET_URL));
    return 0;
}

static int test_name_accessors_never_null(void) {
    CHECK(wake_eclass_name(WAKE_EC_WHO) != NULL);
    CHECK(strcmp(wake_eclass_name(WAKE_EC_WHO), "WHO") == 0);
    CHECK(strcmp(wake_eclass_name(WAKE_EC_WHOM), "WHOM") == 0);
    CHECK(strcmp(wake_eclass_name(WAKE_EC_WITH), "WITH") == 0);
    CHECK(strcmp(wake_eclass_name((wake_eclass_t)99), "UNKNOWN_CLASS") == 0);

    CHECK(strcmp(wake_etype_name(WAKE_ET_IPV4), "IPV4") == 0);
    CHECK(strcmp(wake_etype_name((wake_etype_t)0xff), "UNKNOWN_TYPE") == 0);

    CHECK(strcmp(wake_action_name(WAKE_ACTION_AUTH), "AUTH") == 0);
    CHECK(strcmp(wake_action_name((wake_action_t)99), "UNKNOWN_ACTION") == 0);

    CHECK(strcmp(wake_outcome_name(WAKE_OUTCOME_FAILURE), "FAILURE") == 0);
    CHECK(strcmp(wake_outcome_name((wake_outcome_t)99), "UNKNOWN_OUTCOME") == 0);
    return 0;
}

/* -------------------------------------------------------------------------- */
/* wake_entity_format edge cases                                             */
/* -------------------------------------------------------------------------- */

static int test_format_zero_size_buffer_fails_closed(void) {
    wake_entity_t e;
    wake_entity_init_user(&e, WAKE_EC_WHO, "x", 1);
    CHECK(wake_entity_format(&e, NULL, 0) == -1);
    return 0;
}

static int test_format_truncates_without_overflow(void) {
    wake_entity_t e;
    wake_entity_init_user(&e, WAKE_EC_WHO, "a-fairly-long-username", 22);
    char tiny[6];
    int n = wake_entity_format(&e, tiny, sizeof(tiny));
    CHECK(n == -1); /* buffer too small even for "WHO:USER:" */
    CHECK(tiny[sizeof(tiny) - 1] == '\0');
    return 0;
}

int main(void) {
    struct {
        const char *name;
        int (*fn)(void);
    } cases[] = {
        {"ipv4_roundtrip", test_ipv4_roundtrip},
        {"ipv6_roundtrip", test_ipv6_roundtrip},
        {"str_short_fits_inline", test_str_short_fits_inline},
        {"str_exactly_at_capacity", test_str_exactly_at_capacity},
        {"str_over_capacity_is_hashed", test_str_over_capacity_is_hashed},
        {"hash_fixed_size_entities", test_hash_fixed_size_entities},
        {"numeric_entities", test_numeric_entities},
        {"eq_and_padding_is_deterministic", test_eq_and_padding_is_deterministic},
        {"valid_rejects_corrupt_entities", test_valid_rejects_corrupt_entities},
        {"hash_deterministic_and_key_dependent", test_hash_deterministic_and_key_dependent},
        {"hash_bytes_keyed_independent_of_global_key", test_hash_bytes_keyed_independent_of_global_key},
        {"etype_fixed_len", test_etype_fixed_len},
        {"etype_class_predicates", test_etype_class_predicates},
        {"name_accessors_never_null", test_name_accessors_never_null},
        {"format_zero_size_buffer_fails_closed", test_format_zero_size_buffer_fails_closed},
        {"format_truncates_without_overflow", test_format_truncates_without_overflow},
    };
    int n = (int)(sizeof(cases) / sizeof(cases[0])), i, passed = 0;
    for (i = 0; i < n; i++)
        if (cases[i].fn() == 0) {
            printf("  ok   %s\n", cases[i].name);
            passed++;
        }
    printf("test_entity: %d/%d passed\n", passed, n);
    return g_fail ? 1 : 0;
}
