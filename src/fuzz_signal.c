/*
 * fuzz_signal.c - libFuzzer: untrusted 192-byte wake_signal decode.
 *
 * A compromised peer can send any 192 bytes. verify() must fail closed
 * (magic, version, entity, Ed25519) and never crash.
 *
 * Copyright (c) 2026 Advens. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "wake_signal.h"

#include <stdint.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    wake_signal_t sig;

    memset(&sig, 0, sizeof(sig));
    if (size > sizeof(sig)) {
        size = sizeof(sig);
    }
    if (size > 0) {
        memcpy(&sig, data, size);
    }
    (void)wake_signal_verify(&sig);
    (void)wake_signal_type_name((wake_signal_type_t)sig.meta.signal_type);
    (void)wake_signal_scope_name((wake_signal_scope_t)sig.meta.scope);
    return 0;
}
