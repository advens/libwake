# libwake

C11 library for a distributed detection mesh: membership, epidemic
broadcast, shared confidence, cross-instance correlation, and the
Ed25519/X25519 primitives that authenticate them. No network I/O and no
threads of its own: every module is a passive state machine driven by a
host application's own socket, loop, and clock.

- **wake_swim**: SWIM membership and failure detection (incarnation-based
  state, indirect probing).
- **wake_plumtree**: PlumTree epidemic broadcast (eager/lazy tree,
  IHAVE/GRAFT repair).
- **wake_dgram**: the datagram codec for the two protocols above, bounded,
  fuzzed, safe on untrusted peer input.
- **wake_pheromone**: an mmap-backed, multi-process shared table for
  stigmergic confidence accumulation and decay.
- **wake_quorum**: threshold-based signal emission over a pheromone table
  (observe / alert / retract tiers).
- **wake_tac**: a bounded, lock-free table for transient cross-entity
  coupling (short-lived correlation, not a general graph store).
- **wake_signal**: a signed, fixed-size wire record for a mesh signal
  (entity, verdict, confidence, TTL), Ed25519-authenticated.
- **wake_entity**: the 64-byte entity model shared by every module above
  (source/destination/discriminant, SipHash-keyed).
- **wake_crypto**: SHA-512 and Ed25519 (RFC 8032) for signal
  authentication, X25519 for key agreement, XChaCha20-Poly1305 for AEAD.
  Backed by [Monocypher](https://monocypher.org) 4.0.2 (vendored,
  audited, constant-time).

## In, not in

**In:** the primitives above, unit tests, libFuzzer targets for every
untrusted-input surface (peer datagrams, signed signals, a crafted
pheromone or TAC file), and ASan/UBSan/TSan runs.

**Not in:** a network stack, a config format, cluster bootstrap/discovery
beyond the seed list a caller supplies, and any single global correlator:
`wake_tac` is intentionally per-instance and bounded, not a distributed
graph database.

## Example

```c
#include <wake/wake_pheromone.h>
#include <wake/wake_quorum.h>
#include <arpa/inet.h>
#include <stdio.h>

int main(void)
{
    wake_pheromone_t *pt = wake_pheromone_create("/tmp/example.pht", NULL);
    wake_quorum_t *q = wake_quorum_create(WAKE_PHT_DEFAULT_CAPACITY, NULL);

    wake_entity_t src;
    /* addr_nbo is network-byte-order, as inet_addr() already returns. */
    wake_entity_init_ipv4(&src, WAKE_EC_WHO, inet_addr("203.0.113.7"));

    /* A real caller deposits once per observed event; this simulates three. */
    for (int i = 0; i < 3; i++)
        wake_pheromone_deposit(pt, &src, WAKE_ACTION_AUTH, WAKE_OUTCOME_FAILURE,
                                /*tenant_id=*/1, /*confidence_delta=*/2000, 0);

    wake_quorum_hit_t hits[8];
    uint32_t n = 0;
    wake_quorum_sweep_collect(q, pt, hits, 8, &n);
    for (uint32_t i = 0; i < n; i++) {
        char buf[80];
        wake_entity_format(&hits[i].entry.entity, buf, sizeof(buf));
        printf("%s: %s (confidence=%u)\n",
               wake_quorum_action_name(hits[i].action), buf,
               hits[i].entry.confidence);
    }

    wake_quorum_destroy(q);
    wake_pheromone_close(pt);
    return 0;
}
```

```
cc example.c $(pkg-config --cflags --libs wake) -o example
```

Signing and gossiping that crossing to peers is `wake_signal_init()` +
`wake_ed25519_sign()` + `wake_dgram_encode_pt_gossip()`: see
`src/wake_signal.h` and `src/wake_dgram.h`. Driving the SWIM/PlumTree
state machines from a real socket is the host application's job: see
`src/wake_swim.h` and `src/wake_plumtree.h` for the exact shape (`_tick`,
`_apply_update`, `_recv_*` calls fed by a poll loop and a monotonic clock).

## Build

```
make -f Makefile.port                # shared + static library
make -f Makefile.port test           # every unit test, built against the library
make -f Makefile.port san            # ASan + UBSan
make -f Makefile.port tsan           # wake_tac and wake_pheromone under ThreadSanitizer
make -f Makefile.port libfuzz-ci     # short bounded libFuzzer run per untrusted surface
make -f Makefile.port PREFIX=/usr/local install
```

`pkg-config --cflags --libs wake` after install.

### Dependencies

None beyond a C11 compiler and POSIX (`clock_gettime`, `mmap`). Monocypher
is vendored under `src/vendor/monocypher/`, so there is nothing else to
install for the crypto primitives.

| Platform | Notes |
|----------|-------|
| Linux (glibc) | Any C11 compiler. `make` is GNU Make. |
| FreeBSD | Base `make` is BSD make and cannot parse this Makefile: use `gmake`. |
| macOS | Ships GNU Make as `/usr/bin/make`; works unmodified. |

Dual-arch: `arm64`/`aarch64` builds with `-march=armv8-a+crc`, `x86_64`/`amd64`
with `-march=x86-64-v2 -msse4.2`. Both are safe baselines on hardware from
roughly the last fifteen years; override `ARCHFLAGS` for anything older.

`libfuzz-ci` needs Clang's libFuzzer runtime (`FUZZ_CC ?= clang`); it prints
a skip notice and exits 0 on a toolchain without one (Apple Clang, notably).

## Versioning

The shared-library SONAME is `libwake.so.<MAJOR>` and tracks the C ABI.
`wake_version.h` exposes the same `MAJOR.MINOR.PATCH` at compile time
(`WAKE_VERSION_*`) and at runtime (`wake_version()`, `wake_version_string()`),
so a host can assert it linked against the library it was built against.

Wire and file formats are versioned independently of the library release:

| Surface | Identifier | Notes |
|---------|-----------|-------|
| SWIM / PlumTree datagram | `WAKE_DGRAM_VERSION` = 1 | rejected on mismatch by `wake_dgram_decode()` |
| mesh signal | `WAKE_SIGNAL_VERSION` = 1 | inside the signed 192-byte record |
| pheromone table file | `WAKE_PHT_VERSION` = 1 | checked by `wake_pheromone_open()` |
| TAC table file | `WAKE_TAC_VERSION` = 1 | checked by `wake_tac_open()` |

A struct whose size or layout is part of a wire or file format carries a
`_Static_assert` on its size next to the definition; that assertion failing
on a new platform means the ABI changed, not that the test is wrong.

## Security

Every module that parses bytes from outside the process (a peer datagram,
a signed signal, a pheromone or TAC table file opened from disk) has a
libFuzzer target under `src/fuzz_*.c`, run under AddressSanitizer and
UBSan. `wake_tac` and `wake_pheromone` additionally run under
ThreadSanitizer (`make -f Makefile.port tsan`) since both are mmap-backed
structures shared across processes.

Report a vulnerability privately to the maintainer rather than opening a
public issue.

## License

Apache License 2.0. See [LICENSE](LICENSE). Vendored Monocypher is
BSD-2-Clause OR CC0-1.0; see `src/vendor/monocypher/LICENCE.md`.
