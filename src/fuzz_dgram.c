/*
 * fuzz_dgram.c: fuzz target for the datagram decoder (the untrusted-peer surface)
 *
 * Feeds arbitrary bytes to wake_dgram_decode() and round-trips accepted messages
 * through the encoders. Must run clean under AddressSanitizer + UBSan on any
 * input: no OOB read, no UB.
 *
 * Two front-ends:
 *   libFuzzer (CI):  clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *                          wake_dgram.c fuzz_dgram.c -o fuzz_dgram
 *                    ./fuzz_dgram -max_len=1200 -runs=5000000
 *   standalone:      cc -O1 -DWAKE_DGRAM_FUZZ_STANDALONE -fsanitize=address,undefined \
 *                        wake_dgram.c fuzz_dgram.c -o fuzz_dgram_std
 *                    ./fuzz_dgram_std [iterations]
 *
 * Copyright (c) 2026 Advens. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "wake_dgram.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    wake_dgram_t msg;
    uint8_t out[WAKE_DGRAM_MAX_LEN];

    if (wake_dgram_decode(data, size, &msg) != 0) return 0;

    /* Re-encode every accepted message to exercise the encoders' bounds too. */
    switch (msg.msg_type) {
        case WAKE_DGRAM_SWIM_PING:
        case WAKE_DGRAM_SWIM_ACK:
            wake_dgram_encode_swim(out, sizeof(out), (wake_dgram_type_t)msg.msg_type, msg.sender_id, NULL, msg.updates,
                                 msg.n_updates);
            break;
        case WAKE_DGRAM_SWIM_PING_REQ:
            wake_dgram_encode_swim(out, sizeof(out), WAKE_DGRAM_SWIM_PING_REQ, msg.sender_id, msg.target_id, msg.updates,
                                 msg.n_updates);
            break;
        case WAKE_DGRAM_PT_GOSSIP:
            wake_dgram_encode_pt_gossip(out, sizeof(out), msg.sender_id, &msg.msg_id, msg.payload, msg.payload_len);
            break;
        case WAKE_DGRAM_PT_IHAVE:
        case WAKE_DGRAM_PT_GRAFT:
        case WAKE_DGRAM_PT_PRUNE:
            wake_dgram_encode_pt_ctrl(out, sizeof(out), (wake_dgram_type_t)msg.msg_type, msg.sender_id, &msg.msg_id);
            break;
        default:
            break;
    }
    return 0;
}

#ifdef WAKE_DGRAM_FUZZ_STANDALONE
#include <stdio.h>
#include <stdlib.h>

/* deterministic xorshift64 (reproducible; no wall-clock / rand() dependence) */
static uint64_t rng_state = 0x123456789abcdef0ULL;
static uint64_t xrng(void) {
    uint64_t x = rng_state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    rng_state = x;
    return x;
}

int main(int argc, char **argv) {
    const long iters = (argc > 1) ? atol(argv[1]) : 5000000L;
    const size_t maxlen = WAKE_DGRAM_MAX_LEN + 200; /* also probe past the recv cap */
    uint8_t buf[WAKE_DGRAM_MAX_LEN + 200];
    long i;
    size_t k, len;
    long structured = 0;

    /* 1) structured truncation sweep: a well-formed header of each type followed
     *    by random bytes, at every length 0..600: exercises every off-by-one. */
    for (int t = 0; t <= 8; t++) {
        for (len = 0; len <= 600; len++) {
            for (k = 0; k < len && k < sizeof(buf); k++) buf[k] = (uint8_t)xrng();
            if (len >= 4) {
                buf[0] = 'W';
                buf[1] = 'D';
                buf[2] = 1;
                buf[3] = (uint8_t)t;
            }
            LLVMFuzzerTestOneInput(buf, len < sizeof(buf) ? len : sizeof(buf));
            structured++;
        }
    }

    /* 2) purely random sweep */
    for (i = 0; i < iters; i++) {
        len = (size_t)(xrng() % (maxlen + 1));
        for (k = 0; k < len; k++) buf[k] = (uint8_t)xrng();
        LLVMFuzzerTestOneInput(buf, len);
    }

    printf("wake_dgram fuzz: %ld structured + %ld random inputs, clean (ASan/UBSan)\n", structured, iters);
    return 0;
}
#endif /* WAKE_DGRAM_FUZZ_STANDALONE */
