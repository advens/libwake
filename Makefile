# libwake: portable C library for a distributed detection mesh
# Build system (SO versioning + install targets).
#
# Targets:
#   make           Build shared + static libraries
#   make test      Build and run all tests
#   make install   Install to $(DESTDIR)$(PREFIX)
#   make clean     Remove build artifacts

# --- Configuration ---
PREFIX   ?= /usr/local
DESTDIR  ?=
# Keep in sync with src/wake_version.h's WAKE_VERSION_MAJOR/MINOR/PATCH:
# no generation step ties them together, this comment is the enforcement.
LIB_MAJOR := 0
LIB_MINOR := 3
LIB_PATCH := 0

SONAME   := libwake.so.$(LIB_MAJOR)
SOFILE   := libwake.so.$(LIB_MAJOR).$(LIB_MINOR).$(LIB_PATCH)

# --- Compiler detection ---
CC       ?= cc
AR       ?= ar
CFLAGS   := -std=c11 -Wall -Wextra -Werror -Wpedantic \
            -Wconversion -Wshadow -Wstrict-prototypes \
            -Wmissing-prototypes -Wno-unused-function \
            -fstack-protector-strong -fPIC

# Monocypher is vendored third-party code; relax warnings for it
VENDOR_CFLAGS := -std=c11 -O2 -Wno-conversion -Wno-sign-conversion -fPIC

# Architecture detection
ARCH := $(shell uname -m)
ifeq ($(ARCH),arm64)
    ARCHFLAGS := -march=armv8-a+crc
else ifeq ($(ARCH),aarch64)
    ARCHFLAGS := -march=armv8-a+crc
else ifeq ($(ARCH),x86_64)
    ARCHFLAGS := -march=x86-64-v2 -msse4.2
else ifeq ($(ARCH),amd64)
    ARCHFLAGS := -march=x86-64-v2 -msse4.2
else
    ARCHFLAGS :=
endif

# OS detection
OS := $(shell uname -s)
ifeq ($(OS),FreeBSD)
    LDFLAGS :=
else ifeq ($(OS),Darwin)
    LDFLAGS :=
else
    LDFLAGS := -lm
    # glibc gates POSIX.1-2008 APIs (clock_gettime, ftruncate, CLOCK_REALTIME)
    # behind a feature-test macro under strict -std=c11; FreeBSD and macOS
    # expose them unconditionally.
    CFLAGS += -D_POSIX_C_SOURCE=200809L
endif

# Release by default
CFLAGS += -O2 $(ARCHFLAGS)
VENDOR_CFLAGS += $(ARCHFLAGS)

# Verbose mode
ifeq ($(V),1)
    Q :=
else
    Q := @
endif

# --- Directories ---
SRCDIR    := src
BUILDDIR  := build
VENDORDIR := $(SRCDIR)/vendor/monocypher

# --- Vendor objects (monocypher) ---
VENDOR_OBJS := $(BUILDDIR)/monocypher.o $(BUILDDIR)/monocypher-ed25519.o

# --- WAKE library objects ---
LIB_SRCS := $(SRCDIR)/wake_entity.c $(SRCDIR)/wake_pheromone.c \
            $(SRCDIR)/wake_tac.c \
            $(SRCDIR)/wake_crypto.c $(SRCDIR)/wake_signal.c \
            $(SRCDIR)/wake_quorum.c \
            $(SRCDIR)/wake_swim.c $(SRCDIR)/wake_plumtree.c \
            $(SRCDIR)/wake_dgram.c $(SRCDIR)/wake_version.c
LIB_OBJS := $(patsubst $(SRCDIR)/%.c,$(BUILDDIR)/%.o,$(LIB_SRCS))

ALL_OBJS := $(VENDOR_OBJS) $(LIB_OBJS)

# --- Public headers ---
HEADERS := $(SRCDIR)/wake_entity.h $(SRCDIR)/wake_pheromone.h \
           $(SRCDIR)/wake_tac.h \
           $(SRCDIR)/wake_crypto.h \
           $(SRCDIR)/wake_quorum.h $(SRCDIR)/wake_signal.h \
           $(SRCDIR)/wake_swim.h $(SRCDIR)/wake_plumtree.h \
           $(SRCDIR)/wake_dgram.h $(SRCDIR)/wake_version.h

# --- Rules ---
.PHONY: all test install clean

all: $(BUILDDIR)/$(SOFILE) $(BUILDDIR)/libwake.a

$(BUILDDIR):
	$(Q)mkdir -p $(BUILDDIR)

# Vendor objects (relaxed warnings)
$(BUILDDIR)/monocypher.o: $(VENDORDIR)/monocypher.c | $(BUILDDIR)
	@echo "  CC    $< (vendor)"
	$(Q)$(CC) $(VENDOR_CFLAGS) -c -o $@ $<

$(BUILDDIR)/monocypher-ed25519.o: $(VENDORDIR)/monocypher-ed25519.c | $(BUILDDIR)
	@echo "  CC    $< (vendor)"
	$(Q)$(CC) $(VENDOR_CFLAGS) -I$(VENDORDIR) -c -o $@ $<

# WAKE library objects (strict warnings)
$(BUILDDIR)/%.o: $(SRCDIR)/%.c | $(BUILDDIR)
	@echo "  CC    $<"
	$(Q)$(CC) $(CFLAGS) -c -o $@ $<

# Shared library with SO versioning
$(BUILDDIR)/$(SOFILE): $(ALL_OBJS)
	@echo "  LD    $@"
ifeq ($(OS),Darwin)
	$(Q)$(CC) -dynamiclib -install_name @rpath/$(SONAME) -o $@ $(ALL_OBJS) $(LDFLAGS)
else
	$(Q)$(CC) -shared -Wl,-soname,$(SONAME) -o $@ $(ALL_OBJS) $(LDFLAGS)
endif
	$(Q)ln -sf $(SOFILE) $(BUILDDIR)/$(SONAME)
	$(Q)ln -sf $(SOFILE) $(BUILDDIR)/libwake.so
ifeq ($(OS),Darwin)
	$(Q)ln -sf $(SOFILE) $(BUILDDIR)/libwake.dylib
endif

# Static library
$(BUILDDIR)/libwake.a: $(ALL_OBJS)
	@echo "  AR    $@"
	$(Q)$(AR) rcs $@ $(ALL_OBJS)

# --- Test targets (unit tests built here: test_tac, test_swim, test_dgram,
# test_crypto, test_entity, test_quorum) ---
$(BUILDDIR)/test_tac: $(SRCDIR)/test_tac.c $(BUILDDIR)/libwake.a $(HEADERS) | $(BUILDDIR)
	@echo "  CC    $< (test)"
	$(Q)$(CC) $(CFLAGS) -o $@ $(SRCDIR)/test_tac.c $(BUILDDIR)/libwake.a $(LDFLAGS)

$(BUILDDIR)/test_dgram: $(SRCDIR)/test_dgram.c $(BUILDDIR)/libwake.a $(HEADERS) | $(BUILDDIR)
	@echo "  CC    $< (test)"
	$(Q)$(CC) $(CFLAGS) -o $@ $(SRCDIR)/test_dgram.c $(BUILDDIR)/libwake.a $(LDFLAGS)

.PHONY: test-dgram
test-dgram: $(BUILDDIR)/test_dgram
	@echo "=== wake_dgram codec tests ==="
	$(Q)$(BUILDDIR)/test_dgram

$(BUILDDIR)/test_swim: $(SRCDIR)/test_swim.c $(BUILDDIR)/libwake.a $(HEADERS) | $(BUILDDIR)
	@echo "  CC    $< (test)"
	$(Q)$(CC) $(CFLAGS) -o $@ $(SRCDIR)/test_swim.c $(BUILDDIR)/libwake.a $(LDFLAGS)

.PHONY: test-swim
test-swim: $(BUILDDIR)/test_swim
	@echo "=== wake_swim protocol + health-multiplier tests ==="
	$(Q)$(BUILDDIR)/test_swim

.PHONY: test-tac
test-tac: $(BUILDDIR)/test_tac
	@echo "=== wake_tac invariant tests ==="
	$(Q)$(BUILDDIR)/test_tac

$(BUILDDIR)/test_crypto: $(SRCDIR)/test_crypto.c $(BUILDDIR)/libwake.a $(HEADERS) | $(BUILDDIR)
	@echo "  CC    $< (test)"
	$(Q)$(CC) $(CFLAGS) -o $@ $(SRCDIR)/test_crypto.c $(BUILDDIR)/libwake.a $(LDFLAGS)

.PHONY: test-crypto
test-crypto: $(BUILDDIR)/test_crypto
	@echo "=== wake_crypto known-answer + tamper-rejection tests ==="
	$(Q)$(BUILDDIR)/test_crypto

$(BUILDDIR)/test_entity: $(SRCDIR)/test_entity.c $(BUILDDIR)/libwake.a $(HEADERS) | $(BUILDDIR)
	@echo "  CC    $< (test)"
	$(Q)$(CC) $(CFLAGS) -o $@ $(SRCDIR)/test_entity.c $(BUILDDIR)/libwake.a $(LDFLAGS)

.PHONY: test-entity
test-entity: $(BUILDDIR)/test_entity
	@echo "=== wake_entity construction + hashing tests ==="
	$(Q)$(BUILDDIR)/test_entity

$(BUILDDIR)/test_quorum: $(SRCDIR)/test_quorum.c $(BUILDDIR)/libwake.a $(HEADERS) | $(BUILDDIR)
	@echo "  CC    $< (test)"
	$(Q)$(CC) $(CFLAGS) -o $@ $(SRCDIR)/test_quorum.c $(BUILDDIR)/libwake.a $(LDFLAGS)

.PHONY: test-quorum
test-quorum: $(BUILDDIR)/test_quorum
	@echo "=== wake_quorum threshold + sweep tests ==="
	$(Q)$(BUILDDIR)/test_quorum

# ThreadSanitizer gate: 1 writer (reinforce, batch, decay) vs N readers
# (RPC read path) on one table. Built from sources, not the release lib, so the
# whole call graph is instrumented. Same warning set as the library build
# (minus -Werror so a sanitizer-only warning does not mask the race report).
SAN_CC   ?= $(CC)
SAN_WARN := $(filter-out -Werror,$(CFLAGS))

.PHONY: tsan
tsan: | $(BUILDDIR)
	@echo "=== wake_tac ThreadSanitizer ==="
	$(Q)$(SAN_CC) $(SAN_WARN) -fsanitize=thread -g -O1 -pthread \
		-I$(SRCDIR) $(SRCDIR)/test_tac_tsan.c $(SRCDIR)/wake_tac.c \
		$(SRCDIR)/wake_entity.c -o $(BUILDDIR)/test_tac_tsan
	$(Q)$(BUILDDIR)/test_tac_tsan
	@echo "=== wake_pheromone ThreadSanitizer ==="
	$(Q)$(SAN_CC) $(SAN_WARN) -fsanitize=thread -g -O1 -pthread \
		-I$(SRCDIR) $(SRCDIR)/test_pheromone_tsan.c \
		$(SRCDIR)/wake_pheromone.c $(SRCDIR)/wake_entity.c \
		-o $(BUILDDIR)/test_pheromone_tsan
	$(Q)$(BUILDDIR)/test_pheromone_tsan

# libFuzzer smoke on untrusted byte surfaces. Bounded wall time.
# Linux CI uses clang; Apple Clang often has no fuzzer runtime (skip).
FUZZ_CC ?= clang
FUZZ_CI_FLAGS := -max_total_time=15 -rss_limit_mb=1024 -timeout=8
ifeq ($(OS),Darwin)
FUZZ_ASAN := detect_leaks=0:halt_on_error=1
else
FUZZ_ASAN := detect_leaks=1:halt_on_error=1
endif
FUZZ_CFLAGS := -std=c11 -O1 -g -fsanitize=fuzzer,address,undefined \
               $(ARCHFLAGS) -fPIC -I$(SRCDIR)
ifeq ($(OS),Linux)
FUZZ_CFLAGS += -D_POSIX_C_SOURCE=200809L
endif

.PHONY: libfuzz-ci
libfuzz-ci: | $(BUILDDIR)
	@echo "=== libwake libFuzzer CI (CC=$(FUZZ_CC)) ==="; \
	if ! printf '%s\n' \
	    'int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long n){ (void)d;(void)n; return 0; }' \
	    | $(FUZZ_CC) $(FUZZ_CFLAGS) -x c - -o $(BUILDDIR)/fuzz_probe $(LDFLAGS) 2>/dev/null; then \
	    echo "skip libfuzz-ci: $(FUZZ_CC) has no libFuzzer runtime (expected on Apple Clang)"; \
	    exit 0; \
	fi; \
	$(FUZZ_CC) $(FUZZ_CFLAGS) -I$(VENDORDIR) \
		$(SRCDIR)/fuzz_signal.c $(SRCDIR)/wake_signal.c \
		$(SRCDIR)/wake_crypto.c $(SRCDIR)/wake_entity.c \
		$(VENDORDIR)/monocypher.c $(VENDORDIR)/monocypher-ed25519.c \
		-o $(BUILDDIR)/fuzz_signal $(LDFLAGS); \
	$(FUZZ_CC) $(FUZZ_CFLAGS) \
		$(SRCDIR)/fuzz_swim.c $(SRCDIR)/wake_swim.c \
		-o $(BUILDDIR)/fuzz_swim $(LDFLAGS); \
	$(FUZZ_CC) $(FUZZ_CFLAGS) \
		$(SRCDIR)/fuzz_plumtree.c $(SRCDIR)/wake_plumtree.c \
		-o $(BUILDDIR)/fuzz_plumtree $(LDFLAGS); \
	$(FUZZ_CC) $(FUZZ_CFLAGS) \
		$(SRCDIR)/fuzz_pheromone.c $(SRCDIR)/wake_pheromone.c \
		$(SRCDIR)/wake_entity.c \
		-o $(BUILDDIR)/fuzz_pheromone $(LDFLAGS); \
	$(FUZZ_CC) $(FUZZ_CFLAGS) \
		$(SRCDIR)/fuzz_tac.c $(SRCDIR)/wake_tac.c \
		$(SRCDIR)/wake_entity.c \
		-o $(BUILDDIR)/fuzz_tac $(LDFLAGS); \
	$(FUZZ_CC) $(FUZZ_CFLAGS) \
		$(SRCDIR)/fuzz_dgram.c $(SRCDIR)/wake_dgram.c \
		-o $(BUILDDIR)/fuzz_dgram $(LDFLAGS); \
	$(FUZZ_CC) $(FUZZ_CFLAGS) -I$(VENDORDIR) \
		$(SRCDIR)/fuzz_crypto.c $(SRCDIR)/wake_crypto.c \
		$(VENDORDIR)/monocypher.c $(VENDORDIR)/monocypher-ed25519.c \
		-o $(BUILDDIR)/fuzz_crypto $(LDFLAGS); \
	ASAN_OPTIONS=$(FUZZ_ASAN) UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
		$(BUILDDIR)/fuzz_signal $(FUZZ_CI_FLAGS); \
	ASAN_OPTIONS=$(FUZZ_ASAN) UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
		$(BUILDDIR)/fuzz_swim $(FUZZ_CI_FLAGS); \
	ASAN_OPTIONS=$(FUZZ_ASAN) UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
		$(BUILDDIR)/fuzz_plumtree $(FUZZ_CI_FLAGS); \
	ASAN_OPTIONS=$(FUZZ_ASAN) UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
		$(BUILDDIR)/fuzz_pheromone $(FUZZ_CI_FLAGS); \
	ASAN_OPTIONS=$(FUZZ_ASAN) UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
		$(BUILDDIR)/fuzz_tac $(FUZZ_CI_FLAGS); \
	ASAN_OPTIONS=$(FUZZ_ASAN) UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
		$(BUILDDIR)/fuzz_dgram $(FUZZ_CI_FLAGS); \
	ASAN_OPTIONS=$(FUZZ_ASAN) UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
		$(BUILDDIR)/fuzz_crypto $(FUZZ_CI_FLAGS); \
	echo "libwake libFuzzer CI: signal/swim/plumtree/pheromone/tac/dgram/crypto OK"

# ASan+UBSan run of the invariant suite.
.PHONY: san
san: | $(BUILDDIR)
	@echo "=== wake_tac ASan+UBSan ==="
	$(Q)$(SAN_CC) $(SAN_WARN) -fsanitize=address,undefined -g -O1 \
		-I$(SRCDIR) $(SRCDIR)/test_tac.c $(SRCDIR)/wake_tac.c \
		$(SRCDIR)/wake_entity.c -o $(BUILDDIR)/test_tac_san
	$(Q)$(BUILDDIR)/test_tac_san
	@echo "=== wake_dgram ASan+UBSan ==="
	$(Q)$(SAN_CC) $(SAN_WARN) -fsanitize=address,undefined -g -O1 \
		-I$(SRCDIR) $(SRCDIR)/test_dgram.c $(SRCDIR)/wake_dgram.c \
		-o $(BUILDDIR)/test_dgram_san
	$(Q)$(BUILDDIR)/test_dgram_san
	@echo "=== wake_crypto ASan+UBSan ==="
	$(Q)$(SAN_CC) $(SAN_WARN) -fsanitize=address,undefined -g -O1 \
		-I$(SRCDIR) -I$(VENDORDIR) $(SRCDIR)/test_crypto.c $(SRCDIR)/wake_crypto.c \
		$(VENDORDIR)/monocypher.c $(VENDORDIR)/monocypher-ed25519.c \
		-o $(BUILDDIR)/test_crypto_san
	$(Q)$(BUILDDIR)/test_crypto_san
	@echo "=== wake_quorum ASan+UBSan ==="
	$(Q)$(SAN_CC) $(SAN_WARN) -fsanitize=address,undefined -g -O1 \
		-I$(SRCDIR) $(SRCDIR)/test_quorum.c $(SRCDIR)/wake_quorum.c \
		$(SRCDIR)/wake_pheromone.c $(SRCDIR)/wake_entity.c \
		-o $(BUILDDIR)/test_quorum_san
	$(Q)$(BUILDDIR)/test_quorum_san

test: $(BUILDDIR)/$(SOFILE) $(BUILDDIR)/libwake.a test-tac test-swim test-dgram test-crypto test-entity test-quorum
	@echo ""
	@echo "=== libwake test: link check ==="
	@echo "  Shared library: $(BUILDDIR)/$(SOFILE)"
	@echo "  Static library: $(BUILDDIR)/libwake.a"
	@echo "  Symlinks: $(SONAME) -> $(SOFILE), libwake.so -> $(SOFILE)"
	$(Q)test -L $(BUILDDIR)/$(SONAME) && echo "  OK: $(SONAME) symlink exists"
	$(Q)test -L $(BUILDDIR)/libwake.so && echo "  OK: libwake.so symlink exists"
	@echo "  PASS"

# --- Install ---
# wake.pc.in is pre-substituted into wake.pc by the FreeBSD port's
# do-configure step, which also removes wake.pc.in, so this prerequisite
# must be optional: $(wildcard ...) drops it from the list entirely when
# the file is gone, leaving the already-substituted wake.pc untouched
# instead of making a plain "wake.pc: wake.pc.in" rule fail on a missing
# prerequisite it does not actually need to rebuild.
wake.pc: $(wildcard wake.pc.in)
	@if [ -f wake.pc.in ]; then \
	    echo "  GEN   wake.pc"; \
	    sed -e 's|@PREFIX@|$(PREFIX)|g' \
	        -e 's|@VERSION@|$(LIB_MAJOR).$(LIB_MINOR).$(LIB_PATCH)|g' \
	        wake.pc.in > wake.pc; \
	fi

install: $(BUILDDIR)/$(SOFILE) $(BUILDDIR)/libwake.a wake.pc
	@echo "  INSTALL  $(DESTDIR)$(PREFIX)"
	$(Q)install -d $(DESTDIR)$(PREFIX)/lib
	$(Q)install -d $(DESTDIR)$(PREFIX)/include/wake
	$(Q)install -d $(DESTDIR)$(PREFIX)/libdata/pkgconfig
	$(Q)install -m 0755 $(BUILDDIR)/$(SOFILE) $(DESTDIR)$(PREFIX)/lib/
	$(Q)ln -sf $(SOFILE) $(DESTDIR)$(PREFIX)/lib/$(SONAME)
	$(Q)ln -sf $(SOFILE) $(DESTDIR)$(PREFIX)/lib/libwake.so
	$(Q)install -m 0644 $(BUILDDIR)/libwake.a $(DESTDIR)$(PREFIX)/lib/
	$(Q)install -m 0644 $(HEADERS) $(DESTDIR)$(PREFIX)/include/wake/
	$(Q)install -m 0644 wake.pc $(DESTDIR)$(PREFIX)/libdata/pkgconfig/

clean:
	@echo "  CLEAN"
	$(Q)rm -rf $(BUILDDIR)
	$(Q)rm -f wake.pc
