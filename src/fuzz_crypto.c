/*
 * fuzz_crypto.c: libFuzzer for the two untrusted-input crypto boundaries.
 *
 * A peer supplies an Ed25519 signature and a mesh signal payload to
 * wake_ed25519_verify(); a peer supplies ciphertext, MAC, and associated
 * data to wake_aead_unlock(). Neither must ever crash on any input, and
 * both must fail closed (nonzero) on anything that isn't a genuine match.
 *
 * Data layout (mode selected by the first byte so both surfaces get
 * exercised from the same corpus):
 *   data[0] & 1 == 0: bytes [1..64] sig, [65..96] pubkey, [97..] message
 *                     -> wake_ed25519_verify
 *   data[0] & 1 == 1: bytes [1..32] key, [33..56] nonce, [57..72] mac,
 *                     [73..] ciphertext -> wake_aead_unlock
 *
 * Two front-ends:
 *   libFuzzer (CI):  clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *                          wake_crypto.c fuzz_crypto.c \
 *                          vendor/monocypher/monocypher.c \
 *                          vendor/monocypher/monocypher-ed25519.c \
 *                          -o fuzz_crypto
 *                    ./fuzz_crypto -max_len=512 -runs=5000000
 *   standalone:      cc -O1 -DWAKE_CRYPTO_FUZZ_STANDALONE \
 *                        -fsanitize=address,undefined ... -o fuzz_crypto_std
 *                    ./fuzz_crypto_std [iterations]
 *
 * Copyright (c) 2026 Advens. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "wake_crypto.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;

    if ((data[0] & 1) == 0) {
        if (size < 1 + 64 + 32) return 0;
        const uint8_t *sig = data + 1;
        const uint8_t *pk = data + 1 + 64;
        const uint8_t *msg = data + 1 + 64 + 32;
        size_t msg_len = size - (1 + 64 + 32);
        (void)wake_ed25519_verify(sig, msg, msg_len, pk);
    } else {
        if (size < 1 + 32 + 24 + 16) return 0;
        const uint8_t *key = data + 1;
        const uint8_t *nonce = data + 1 + 32;
        const uint8_t *mac = data + 1 + 32 + 24;
        const uint8_t *ct = data + 1 + 32 + 24 + 16;
        size_t ct_len = size - (1 + 32 + 24 + 16);
        if (ct_len > 4096) return 0; /* bound the scratch buffer below */
        uint8_t pt[4096];
        (void)wake_aead_unlock(pt, mac, key, nonce, NULL, 0, ct, ct_len);
    }
    return 0;
}

#ifdef WAKE_CRYPTO_FUZZ_STANDALONE
#include <stdio.h>
#include <stdlib.h>

static uint64_t rng_state = 0xc0ffee1234567890ULL;
static uint64_t xrng(void) {
    uint64_t x = rng_state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    rng_state = x;
    return x;
}

int main(int argc, char **argv) {
    const long iters = (argc > 1) ? atol(argv[1]) : 2000000L;
    const size_t maxlen = 512;
    uint8_t buf[512];
    long i;
    size_t k, len;

    for (i = 0; i < iters; i++) {
        len = (size_t)(xrng() % (maxlen + 1));
        for (k = 0; k < len; k++) buf[k] = (uint8_t)xrng();
        LLVMFuzzerTestOneInput(buf, len);
    }
    printf("fuzz_crypto: %ld random inputs, clean (ASan/UBSan)\n", iters);
    return 0;
}
#endif /* WAKE_CRYPTO_FUZZ_STANDALONE */
