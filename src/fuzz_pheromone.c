/*
 * fuzz_pheromone.c - libFuzzer: mmap-open of a crafted pheromone file.
 *
 * A crashed or attacker-written file must fail magic/version closed
 * (NULL) and never crash or over-map.
 *
 * Copyright (c) 2026 Advens. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "wake_pheromone.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char path[] = "/tmp/wakefuzz_pht.XXXXXX";
    int fd;
    wake_pheromone_t *pt;
    ssize_t w;

    if (size > (1u << 20)) {
        size = 1u << 20;
    }
    fd = mkstemp(path);
    if (fd < 0) {
        return 0;
    }
    if (size > 0) {
        w = write(fd, data, size);
        (void)w;
    }
    close(fd);

    pt = wake_pheromone_open(path);
    if (pt != NULL) {
        wake_pheromone_close(pt);
    }
    unlink(path);
    return 0;
}
