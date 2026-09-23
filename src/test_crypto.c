/*
 * test_crypto.c: wake_crypto correctness tests
 *
 * Known-answer tests against the public FIPS 180-4 / RFC 8032 test vectors
 * (not just internal round-trips: a self-consistent bug can still pass a
 * round-trip test), plus the tamper-rejection properties the mesh signal
 * path depends on. No network, no /dev/urandom in the deterministic cases.
 *
 * Copyright (c) 2026 Advens. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "wake_crypto.h"

#include <stdio.h>
#include <string.h>

static int g_fail;

#define CHECK(cond)                                                          \
    do {                                                                     \
        if (!(cond)) {                                                       \
            printf("  FAIL %s:%d  %s\n", __func__, __LINE__, #cond);         \
            g_fail = 1;                                                      \
            return 1;                                                        \
        }                                                                    \
    } while (0)

static void hex_decode(const char *hex, uint8_t *out, size_t out_len) {
    for (size_t i = 0; i < out_len; i++) {
        unsigned v;
        sscanf(hex + 2 * i, "%2x", &v);
        out[i] = (uint8_t)v;
    }
}

/* -------------------------------------------------------------------------- */
/* SHA-512: FIPS 180-4 / common known-answer vectors                         */
/* -------------------------------------------------------------------------- */

static int test_sha512_empty_string(void) {
    uint8_t out[64];
    uint8_t want[64];
    /* FIPS 180-4 known-answer vector for SHA-512(""). */
    hex_decode("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9c"
               "e47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
               want, 64);
    wake_sha512("", 0, out);
    CHECK(memcmp(out, want, 64) == 0);
    return 0;
}

static int test_sha512_abc(void) {
    uint8_t out[64];
    uint8_t want[64];
    /* FIPS 180-4 known-answer vector for SHA-512("abc"). */
    hex_decode("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39"
               "a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
               want, 64);
    wake_sha512("abc", 3, out);
    CHECK(memcmp(out, want, 64) == 0);
    return 0;
}

/* -------------------------------------------------------------------------- */
/* Ed25519: cross-library known-answer vector                                */
/*                                                                            */
/* Generated independently with Python's `cryptography` (OpenSSL backend):   */
/*   seed = bytes(range(32)); Ed25519PrivateKey.from_private_bytes(seed)     */
/*   sign(b"")                                                               */
/* Monocypher producing byte-identical output to OpenSSL for the same seed   */
/* and message is a real cross-implementation check, not just internal      */
/* self-consistency.                                                        */
/* -------------------------------------------------------------------------- */

static int test_ed25519_cross_library_vector(void) {
    uint8_t seed[32], want_pk[32], want_sig[64];
    for (int i = 0; i < 32; i++)
        seed[i] = (uint8_t)i;
    hex_decode("03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8",
               want_pk, 32);
    hex_decode("9ca53579530654d5c3df77089ef45eda613e2fedf670e96bedac4639504e5845e"
               "f4b95d5793077233dd16817b2532e9c5525872a73a4ad74b759369a9e05c102",
               want_sig, 64);

    wake_node_key_t key;
    wake_ed25519_keygen_from_seed(&key, seed);
    CHECK(memcmp(key.public_key, want_pk, 32) == 0);

    uint8_t sig[64];
    wake_ed25519_sign(sig, "", 0, &key);
    CHECK(memcmp(sig, want_sig, 64) == 0);
    CHECK(wake_ed25519_verify(sig, "", 0, key.public_key) == 0);
    return 0;
}

static int test_ed25519_keygen_from_seed_deterministic(void) {
    uint8_t seed[32];
    memset(seed, 0x42, 32);
    wake_node_key_t a, b;
    wake_ed25519_keygen_from_seed(&a, seed);
    wake_ed25519_keygen_from_seed(&b, seed);
    CHECK(memcmp(a.public_key, b.public_key, 32) == 0);
    CHECK(memcmp(a.secret_key, b.secret_key, 64) == 0);
    /* Layout is seed(32) || public_key(32), per wake_crypto.h. */
    CHECK(memcmp(a.secret_key, seed, 32) == 0);
    CHECK(memcmp(a.secret_key + 32, a.public_key, 32) == 0);
    return 0;
}

static int test_ed25519_different_seeds_differ(void) {
    uint8_t seed_a[32], seed_b[32];
    memset(seed_a, 0x01, 32);
    memset(seed_b, 0x02, 32);
    wake_node_key_t a, b;
    wake_ed25519_keygen_from_seed(&a, seed_a);
    wake_ed25519_keygen_from_seed(&b, seed_b);
    CHECK(memcmp(a.public_key, b.public_key, 32) != 0);
    return 0;
}

static int test_ed25519_keygen_random_distinct(void) {
    wake_node_key_t a, b;
    CHECK(wake_ed25519_keygen(&a) == 0);
    CHECK(wake_ed25519_keygen(&b) == 0);
    CHECK(memcmp(a.public_key, b.public_key, 32) != 0);
    return 0;
}

static int test_ed25519_verify_rejects_tampered_message(void) {
    uint8_t seed[32];
    memset(seed, 0x07, 32);
    wake_node_key_t key;
    wake_ed25519_keygen_from_seed(&key, seed);

    const char *msg = "the quick brown fox";
    uint8_t sig[64];
    wake_ed25519_sign(sig, msg, strlen(msg), &key);
    CHECK(wake_ed25519_verify(sig, msg, strlen(msg), key.public_key) == 0);

    char tampered[32];
    strcpy(tampered, msg);
    tampered[4] ^= 0x01;
    CHECK(wake_ed25519_verify(sig, tampered, strlen(msg), key.public_key) != 0);
    return 0;
}

static int test_ed25519_verify_rejects_tampered_signature(void) {
    uint8_t seed[32];
    memset(seed, 0x08, 32);
    wake_node_key_t key;
    wake_ed25519_keygen_from_seed(&key, seed);

    const char *msg = "immutable";
    uint8_t sig[64];
    wake_ed25519_sign(sig, msg, strlen(msg), &key);
    sig[0] ^= 0x01;
    CHECK(wake_ed25519_verify(sig, msg, strlen(msg), key.public_key) != 0);
    return 0;
}

static int test_ed25519_verify_rejects_wrong_key(void) {
    uint8_t seed_a[32], seed_b[32];
    memset(seed_a, 0x09, 32);
    memset(seed_b, 0x0a, 32);
    wake_node_key_t a, b;
    wake_ed25519_keygen_from_seed(&a, seed_a);
    wake_ed25519_keygen_from_seed(&b, seed_b);

    const char *msg = "signed by a";
    uint8_t sig[64];
    wake_ed25519_sign(sig, msg, strlen(msg), &a);
    CHECK(wake_ed25519_verify(sig, msg, strlen(msg), a.public_key) == 0);
    CHECK(wake_ed25519_verify(sig, msg, strlen(msg), b.public_key) != 0);
    return 0;
}

static int test_ed25519_empty_message(void) {
    uint8_t seed[32];
    memset(seed, 0x0b, 32);
    wake_node_key_t key;
    wake_ed25519_keygen_from_seed(&key, seed);
    uint8_t sig[64];
    wake_ed25519_sign(sig, NULL, 0, &key);
    CHECK(wake_ed25519_verify(sig, NULL, 0, key.public_key) == 0);
    return 0;
}

/* -------------------------------------------------------------------------- */
/* X25519: Diffie-Hellman shared-secret agreement                            */
/* -------------------------------------------------------------------------- */

static int test_x25519_shared_secret_agrees(void) {
    uint8_t alice_sk[32], bob_sk[32];
    memset(alice_sk, 0x11, 32);
    memset(bob_sk, 0x22, 32);

    uint8_t alice_pk[32], bob_pk[32];
    wake_x25519_public_key(alice_pk, alice_sk);
    wake_x25519_public_key(bob_pk, bob_sk);
    CHECK(memcmp(alice_pk, bob_pk, 32) != 0);

    uint8_t shared_a[32], shared_b[32];
    wake_x25519(shared_a, alice_sk, bob_pk);
    wake_x25519(shared_b, bob_sk, alice_pk);
    CHECK(memcmp(shared_a, shared_b, 32) == 0);
    return 0;
}

static int test_x25519_different_peers_different_secret(void) {
    uint8_t alice_sk[32], bob_sk[32], carol_sk[32];
    memset(alice_sk, 0x33, 32);
    memset(bob_sk, 0x44, 32);
    memset(carol_sk, 0x55, 32);

    uint8_t bob_pk[32], carol_pk[32];
    wake_x25519_public_key(bob_pk, bob_sk);
    wake_x25519_public_key(carol_pk, carol_sk);

    uint8_t with_bob[32], with_carol[32];
    wake_x25519(with_bob, alice_sk, bob_pk);
    wake_x25519(with_carol, alice_sk, carol_pk);
    CHECK(memcmp(with_bob, with_carol, 32) != 0);
    return 0;
}

static int test_eddsa_to_x25519_reuses_identity(void) {
    uint8_t seed_a[32], seed_b[32];
    memset(seed_a, 0x66, 32);
    memset(seed_b, 0x77, 32);

    uint8_t x_sk_a[32], x_sk_b[32];
    wake_eddsa_to_x25519(x_sk_a, seed_a);
    wake_eddsa_to_x25519(x_sk_b, seed_b);
    CHECK(memcmp(x_sk_a, x_sk_b, 32) != 0);

    uint8_t x_pk_a[32], x_pk_b[32];
    wake_x25519_public_key(x_pk_a, x_sk_a);
    wake_x25519_public_key(x_pk_b, x_sk_b);

    uint8_t shared_a[32], shared_b[32];
    wake_x25519(shared_a, x_sk_a, x_pk_b);
    wake_x25519(shared_b, x_sk_b, x_pk_a);
    CHECK(memcmp(shared_a, shared_b, 32) == 0);

    /* Deterministic: converting the same Ed25519 seed twice agrees. */
    uint8_t x_sk_a_again[32];
    wake_eddsa_to_x25519(x_sk_a_again, seed_a);
    CHECK(memcmp(x_sk_a, x_sk_a_again, 32) == 0);
    return 0;
}

/* -------------------------------------------------------------------------- */
/* XChaCha20-Poly1305 AEAD                                                    */
/* -------------------------------------------------------------------------- */

static int test_aead_roundtrip(void) {
    uint8_t key[32], nonce[24];
    memset(key, 0xaa, 32);
    memset(nonce, 0xbb, 24);
    const char *ad = "header";
    const char *pt = "the mesh signal payload";
    size_t pt_len = strlen(pt);

    uint8_t ct[64], mac[16], out[64];
    wake_aead_lock(ct, mac, key, nonce, (const uint8_t *)ad, strlen(ad),
                   (const uint8_t *)pt, pt_len);
    CHECK(memcmp(ct, pt, pt_len) != 0); /* ciphertext isn't the plaintext */
    CHECK(wake_aead_unlock(out, mac, key, nonce, (const uint8_t *)ad, strlen(ad),
                            ct, pt_len) == 0);
    CHECK(memcmp(out, pt, pt_len) == 0);
    return 0;
}

static int test_aead_empty_plaintext(void) {
    uint8_t key[32], nonce[24], mac[16];
    memset(key, 0xcc, 32);
    memset(nonce, 0xdd, 24);
    wake_aead_lock(NULL, mac, key, nonce, NULL, 0, NULL, 0);
    CHECK(wake_aead_unlock(NULL, mac, key, nonce, NULL, 0, NULL, 0) == 0);
    return 0;
}

static int test_aead_rejects_tampered_ciphertext(void) {
    uint8_t key[32], nonce[24];
    memset(key, 0x01, 32);
    memset(nonce, 0x02, 24);
    const char *pt = "0123456789abcdef";
    size_t len = strlen(pt);

    uint8_t ct[32], mac[16], out[32];
    wake_aead_lock(ct, mac, key, nonce, NULL, 0, (const uint8_t *)pt, len);
    ct[0] ^= 0x01;
    CHECK(wake_aead_unlock(out, mac, key, nonce, NULL, 0, ct, len) != 0);
    return 0;
}

static int test_aead_rejects_tampered_mac(void) {
    uint8_t key[32], nonce[24];
    memset(key, 0x03, 32);
    memset(nonce, 0x04, 24);
    const char *pt = "authenticate me";
    size_t len = strlen(pt);

    uint8_t ct[32], mac[16], out[32];
    wake_aead_lock(ct, mac, key, nonce, NULL, 0, (const uint8_t *)pt, len);
    mac[0] ^= 0x01;
    CHECK(wake_aead_unlock(out, mac, key, nonce, NULL, 0, ct, len) != 0);
    return 0;
}

static int test_aead_rejects_tampered_associated_data(void) {
    uint8_t key[32], nonce[24];
    memset(key, 0x05, 32);
    memset(nonce, 0x06, 24);
    const char *ad = "wake_signal_meta";
    const char *pt = "payload";
    size_t len = strlen(pt);

    uint8_t ct[32], mac[16], out[32];
    wake_aead_lock(ct, mac, key, nonce, (const uint8_t *)ad, strlen(ad),
                   (const uint8_t *)pt, len);
    CHECK(wake_aead_unlock(out, mac, key, nonce, (const uint8_t *)"wake_signal_metb",
                            strlen(ad), ct, len) != 0);
    return 0;
}

static int test_aead_rejects_wrong_key(void) {
    uint8_t key[32], other_key[32], nonce[24];
    memset(key, 0x0e, 32);
    memset(other_key, 0x0f, 32);
    memset(nonce, 0x10, 24);
    const char *pt = "confidential";
    size_t len = strlen(pt);

    uint8_t ct[32], mac[16], out[32];
    wake_aead_lock(ct, mac, key, nonce, NULL, 0, (const uint8_t *)pt, len);
    CHECK(wake_aead_unlock(out, mac, other_key, nonce, NULL, 0, ct, len) != 0);
    return 0;
}

static int test_aead_wrong_nonce_fails(void) {
    uint8_t key[32], nonce[24], other_nonce[24];
    memset(key, 0x12, 32);
    memset(nonce, 0x13, 24);
    memset(other_nonce, 0x14, 24);
    const char *pt = "nonce matters";
    size_t len = strlen(pt);

    uint8_t ct[32], mac[16], out[32];
    wake_aead_lock(ct, mac, key, nonce, NULL, 0, (const uint8_t *)pt, len);
    CHECK(wake_aead_unlock(out, mac, key, other_nonce, NULL, 0, ct, len) != 0);
    return 0;
}

/* -------------------------------------------------------------------------- */
/* Secure wipe                                                                */
/* -------------------------------------------------------------------------- */

static int test_crypto_wipe_zeroes(void) {
    uint8_t buf[64];
    memset(buf, 0xff, sizeof(buf));
    wake_crypto_wipe(buf, sizeof(buf));
    for (size_t i = 0; i < sizeof(buf); i++)
        CHECK(buf[i] == 0);
    return 0;
}

/* -------------------------------------------------------------------------- */

int main(void) {
    struct {
        const char *name;
        int (*fn)(void);
    } cases[] = {
        {"sha512_empty_string", test_sha512_empty_string},
        {"sha512_abc", test_sha512_abc},
        {"ed25519_cross_library_vector", test_ed25519_cross_library_vector},
        {"ed25519_keygen_from_seed_deterministic", test_ed25519_keygen_from_seed_deterministic},
        {"ed25519_different_seeds_differ", test_ed25519_different_seeds_differ},
        {"ed25519_keygen_random_distinct", test_ed25519_keygen_random_distinct},
        {"ed25519_verify_rejects_tampered_message", test_ed25519_verify_rejects_tampered_message},
        {"ed25519_verify_rejects_tampered_signature", test_ed25519_verify_rejects_tampered_signature},
        {"ed25519_verify_rejects_wrong_key", test_ed25519_verify_rejects_wrong_key},
        {"ed25519_empty_message", test_ed25519_empty_message},
        {"x25519_shared_secret_agrees", test_x25519_shared_secret_agrees},
        {"x25519_different_peers_different_secret", test_x25519_different_peers_different_secret},
        {"eddsa_to_x25519_reuses_identity", test_eddsa_to_x25519_reuses_identity},
        {"aead_roundtrip", test_aead_roundtrip},
        {"aead_empty_plaintext", test_aead_empty_plaintext},
        {"aead_rejects_tampered_ciphertext", test_aead_rejects_tampered_ciphertext},
        {"aead_rejects_tampered_mac", test_aead_rejects_tampered_mac},
        {"aead_rejects_tampered_associated_data", test_aead_rejects_tampered_associated_data},
        {"aead_rejects_wrong_key", test_aead_rejects_wrong_key},
        {"aead_wrong_nonce_fails", test_aead_wrong_nonce_fails},
        {"crypto_wipe_zeroes", test_crypto_wipe_zeroes},
    };
    int n = (int)(sizeof(cases) / sizeof(cases[0])), i, passed = 0;
    for (i = 0; i < n; i++)
        if (cases[i].fn() == 0) {
            printf("  ok   %s\n", cases[i].name);
            passed++;
        }
    printf("test_crypto: %d/%d passed\n", passed, n);
    return g_fail ? 1 : 0;
}
