/*
 * wake_version.h: libwake release version
 *
 * MAJOR/MINOR/PATCH mirror the SONAME-driving LIB_MAJOR/LIB_MINOR/LIB_PATCH
 * variables in Makefile.port; the build's libwake.so.$(LIB_MAJOR) versioning
 * and this header are two views of the same number and must be bumped
 * together. There is no generation step tying them automatically; this
 * comment is the enforcement until one exists.
 *
 * Copyright (c) 2026 Advens. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef WAKE_VERSION_H
#define WAKE_VERSION_H

#ifdef __cplusplus
extern "C" {
#endif

#define WAKE_VERSION_MAJOR 0
#define WAKE_VERSION_MINOR 3
#define WAKE_VERSION_PATCH 0

#define WAKE_VERSION_STRING "0.3.0"

/* Single comparable integer: (major << 16) | (minor << 8) | patch.
 * Use for #if WAKE_VERSION_NUM >= ... feature checks across releases. */
#define WAKE_VERSION_NUM \
    ((WAKE_VERSION_MAJOR << 16) | (WAKE_VERSION_MINOR << 8) | WAKE_VERSION_PATCH)

/* Runtime accessors: the version of the libwake actually LINKED, which can
 * differ from the WAKE_VERSION_* macros a caller was compiled against if it
 * dynamic-links a different installed version (e.g. a plugin built against
 * one libwake.so loading a system libwake.so from another release). These
 * are real exported symbols defined in wake_version.c, deliberately NOT
 * static inline: an inline body would compile the CALLER's own macro values
 * into the caller, which defeats the point of a runtime check. */
const char *wake_version_string(void);
void wake_version(int *major, int *minor, int *patch);

#ifdef __cplusplus
}
#endif

#endif /* WAKE_VERSION_H */
