/*
 * wake_crypto.h: WAKE Cryptographic Primitives
 *
 * SHA-512 and Ed25519 (RFC 8032) for mesh signal authentication.
 * Each node has an Ed25519 keypair. Ed25519 over the signal body, for
 * tamper detection and attribution to the current signer; a forwarder
 * re-signs.
 *
 * Backend: Monocypher 4.0.2 (audited, constant-time, BSD-2/CC0).
 * This header provides the WAKE-specific API; the monocypher
 * dependency is an implementation detail hidden behind it.
 *
 * Copyright (c) 2026 Advens. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef WAKE_CRYPTO_H
#define WAKE_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* --------------------------------------------------------------------------
 * Constants
 * -------------------------------------------------------------------------- */

#define WAKE_SHA512_DIGEST_LEN  64
#define WAKE_ED25519_PK_LEN     32
#define WAKE_ED25519_SK_LEN     64   /* seed(32) || public_key(32) */
#define WAKE_ED25519_SEED_LEN   32
#define WAKE_ED25519_SIG_LEN    64

/* --------------------------------------------------------------------------
 * SHA-512: one-shot hash
 * -------------------------------------------------------------------------- */

void wake_sha512(const void *data, size_t len, uint8_t out[64]);

/* --------------------------------------------------------------------------
 * Ed25519 keypair
 * -------------------------------------------------------------------------- */

typedef struct {
    uint8_t public_key[WAKE_ED25519_PK_LEN];
    uint8_t secret_key[WAKE_ED25519_SK_LEN];
} wake_node_key_t;

/*
 * Generate an Ed25519 keypair from system randomness (/dev/urandom).
 * Returns 0 on success, -1 on failure.
 */
int wake_ed25519_keygen(wake_node_key_t *key);

/*
 * Generate an Ed25519 keypair from a 32-byte seed (deterministic).
 */
void wake_ed25519_keygen_from_seed(wake_node_key_t *key,
                                    const uint8_t seed[32]);

/* --------------------------------------------------------------------------
 * Ed25519 sign / verify
 * -------------------------------------------------------------------------- */

/*
 * Sign a message. Produces a 64-byte Ed25519 signature.
 */
void wake_ed25519_sign(uint8_t sig_out[64],
                        const void *msg, size_t msg_len,
                        const wake_node_key_t *key);

/*
 * Verify an Ed25519 signature.
 * Returns 0 if valid, -1 if invalid.
 */
int wake_ed25519_verify(const uint8_t sig[64],
                         const void *msg, size_t msg_len,
                         const uint8_t public_key[32]);

/* --------------------------------------------------------------------------
 * X25519 Diffie-Hellman key exchange
 * -------------------------------------------------------------------------- */

#define WAKE_X25519_KEY_LEN     32
#define WAKE_AEAD_NONCE_LEN     24
#define WAKE_AEAD_MAC_LEN       16

/*
 * Compute X25519 public key from a 32-byte secret key.
 */
void wake_x25519_public_key(uint8_t pk[32], const uint8_t sk[32]);

/*
 * X25519 Diffie-Hellman: compute shared secret from my secret + their public.
 * The raw shared secret should be hashed before use as a symmetric key.
 */
void wake_x25519(uint8_t shared[32],
                 const uint8_t my_sk[32],
                 const uint8_t their_pk[32]);

/*
 * Convert an Ed25519 secret key seed (32 bytes) to an X25519 secret key.
 * Enables reuse of Ed25519 identity for X25519 key agreement.
 */
void wake_eddsa_to_x25519(uint8_t x25519_sk[32],
                           const uint8_t ed25519_seed[32]);

/* --------------------------------------------------------------------------
 * XChaCha20-Poly1305 AEAD
 * -------------------------------------------------------------------------- */

/*
 * Authenticated encryption. Produces ciphertext + 16-byte MAC.
 * 24-byte nonce, supplied by the caller. Do not reuse a nonce with the
 * same key; a random nonce only makes a collision unlikely.
 */
void wake_aead_lock(uint8_t *ct, uint8_t mac[16],
                    const uint8_t key[32], const uint8_t nonce[24],
                    const uint8_t *ad, size_t ad_len,
                    const uint8_t *pt, size_t pt_len);

/*
 * Authenticated decryption. Returns 0 on success, -1 on auth failure.
 */
int  wake_aead_unlock(uint8_t *pt, const uint8_t mac[16],
                      const uint8_t key[32], const uint8_t nonce[24],
                      const uint8_t *ad, size_t ad_len,
                      const uint8_t *ct, size_t ct_len);

/* --------------------------------------------------------------------------
 * Secure memory wipe
 * -------------------------------------------------------------------------- */

/*
 * Constant-time wipe of sensitive data (keys, seeds).
 * Cannot be optimized out by the compiler.
 */
void wake_crypto_wipe(void *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* WAKE_CRYPTO_H */
