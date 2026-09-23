/*
 * wake_crypto.c: WAKE Cryptographic Primitives (Monocypher 4.0.2 backend)
 *
 * Thin wrapper around Monocypher for SHA-512 (FIPS 180-4) and
 * Ed25519 (RFC 8032). All constant-time guarantees come from monocypher.
 *
 * Copyright (c) 2026 Advens. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "wake_crypto.h"
#include "vendor/monocypher/monocypher.h"
#include "vendor/monocypher/monocypher-ed25519.h"

#include <fcntl.h>
#include <string.h>
#include <unistd.h>

/* =========================================================================
 * SHA-512
 * ========================================================================= */

void
wake_sha512(const void *data, size_t len, uint8_t out[64])
{
    crypto_sha512(out, (const uint8_t *)data, len);
}

/* =========================================================================
 * Ed25519 key generation
 * ========================================================================= */

void
wake_ed25519_keygen_from_seed(wake_node_key_t *key,
                               const uint8_t seed[32])
{
    /*
     * crypto_ed25519_key_pair(secret_key, public_key, seed):
     *   - Expands seed via SHA-512 + clamping → secret_key[64]
     *   - Derives public_key[32] from the clamped scalar
     *   - WARNING: monocypher wipes the seed parameter
     *
     * Our wake_node_key_t layout:
     *   secret_key = seed(32) || public_key(32)   (NaCl/libsodium convention)
     *
     * We keep the seed in our struct for re-derivation during sign().
     */
    uint8_t seed_copy[32];
    memcpy(seed_copy, seed, 32);

    uint8_t expanded_sk[64];
    crypto_ed25519_key_pair(expanded_sk, key->public_key, seed_copy);

    /* Store seed || public_key */
    memcpy(key->secret_key, seed, 32);
    memcpy(key->secret_key + 32, key->public_key, 32);

    crypto_wipe(expanded_sk, sizeof(expanded_sk));
    crypto_wipe(seed_copy, sizeof(seed_copy));
}

int
wake_ed25519_keygen(wake_node_key_t *key)
{
    uint8_t seed[32];

    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0)
        return -1;

    ssize_t n = read(fd, seed, sizeof(seed));
    close(fd);

    if (n != (ssize_t)sizeof(seed))
        return -1;

    wake_ed25519_keygen_from_seed(key, seed);
    crypto_wipe(seed, sizeof(seed));

    return 0;
}

/* =========================================================================
 * Ed25519 sign / verify
 * ========================================================================= */

void
wake_ed25519_sign(uint8_t sig_out[64],
                   const void *msg, size_t msg_len,
                   const wake_node_key_t *key)
{
    /*
     * Monocypher's crypto_ed25519_sign() expects the expanded
     * secret key (64 bytes from key_pair), not the raw seed.
     * Re-derive it from our stored seed (first 32 bytes of secret_key).
     */
    uint8_t seed_copy[32];
    memcpy(seed_copy, key->secret_key, 32);

    uint8_t expanded_sk[64];
    uint8_t pk_discard[32];
    crypto_ed25519_key_pair(expanded_sk, pk_discard, seed_copy);

    crypto_ed25519_sign(sig_out, expanded_sk,
                         (const uint8_t *)msg, msg_len);

    crypto_wipe(expanded_sk, sizeof(expanded_sk));
    crypto_wipe(seed_copy, sizeof(seed_copy));
    crypto_wipe(pk_discard, sizeof(pk_discard));
}

int
wake_ed25519_verify(const uint8_t sig[64],
                     const void *msg, size_t msg_len,
                     const uint8_t public_key[32])
{
    return crypto_ed25519_check(sig, public_key,
                                 (const uint8_t *)msg, msg_len);
}

/* =========================================================================
 * X25519 Diffie-Hellman
 * ========================================================================= */

void
wake_x25519_public_key(uint8_t pk[32], const uint8_t sk[32])
{
    crypto_x25519_public_key(pk, sk);
}

void
wake_x25519(uint8_t shared[32],
            const uint8_t my_sk[32],
            const uint8_t their_pk[32])
{
    crypto_x25519(shared, my_sk, their_pk);
}

void
wake_eddsa_to_x25519(uint8_t x25519_sk[32],
                      const uint8_t ed25519_seed[32])
{
    crypto_eddsa_to_x25519(x25519_sk, ed25519_seed);
}

/* =========================================================================
 * XChaCha20-Poly1305 AEAD
 * ========================================================================= */

void
wake_aead_lock(uint8_t *ct, uint8_t mac[16],
               const uint8_t key[32], const uint8_t nonce[24],
               const uint8_t *ad, size_t ad_len,
               const uint8_t *pt, size_t pt_len)
{
    crypto_aead_lock(ct, mac, key, nonce, ad, ad_len, pt, pt_len);
}

int
wake_aead_unlock(uint8_t *pt, const uint8_t mac[16],
                 const uint8_t key[32], const uint8_t nonce[24],
                 const uint8_t *ad, size_t ad_len,
                 const uint8_t *ct, size_t ct_len)
{
    return crypto_aead_unlock(pt, mac, key, nonce, ad, ad_len, ct, ct_len);
}

/* =========================================================================
 * Secure wipe
 * ========================================================================= */

void
wake_crypto_wipe(void *buf, size_t len)
{
    crypto_wipe(buf, len);
}
