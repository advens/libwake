/*
 * wake_version.c: libwake release version (runtime accessors)
 *
 * Copyright (c) 2026 Advens. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "wake_version.h"

const char *
wake_version_string(void)
{
    return WAKE_VERSION_STRING;
}

void
wake_version(int *major, int *minor, int *patch)
{
    if (major) *major = WAKE_VERSION_MAJOR;
    if (minor) *minor = WAKE_VERSION_MINOR;
    if (patch) *patch = WAKE_VERSION_PATCH;
}
