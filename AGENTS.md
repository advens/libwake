# AGENTS.md

C11 library for a distributed detection mesh: membership, epidemic
broadcast, shared confidence, cross-instance correlation, and the
Ed25519/X25519 primitives that authenticate them. No network I/O and no
threads of its own: every module is a passive state machine driven by a
host application's own socket, loop, and clock.

Read `docs/COMMIT.md` and `docs/BRANCHES.md` before any
commit-shaped or branch-shaped output. You do not commit, push,
or tag. The human does, using those contracts. Work branches are
`<type>/<scope>-<slug>`. Never push `main`.

## Build and test

```
make                # shared + static library
make test           # every unit test, built against the library
make san            # ASan + UBSan
make tsan           # wake_tac and wake_pheromone under ThreadSanitizer
make libfuzz-ci     # short bounded libFuzzer run per untrusted surface
```

Requires a C11 compiler and POSIX (`clock_gettime`, `mmap`). Monocypher
is vendored under `src/vendor/monocypher/`, so there is nothing else to
install for the crypto primitives. `libfuzz-ci` needs Clang's libFuzzer
runtime (`FUZZ_CC ?= clang`); it prints a skip notice and exits 0 on a
toolchain without one (Apple Clang, notably). Dual-arch: `arm64`/`aarch64`
builds with `-march=armv8-a+crc`, `x86_64`/`amd64` with
`-march=x86-64-v2 -msse4.2`. Both are safe baselines on hardware from
roughly the last fifteen years; override `ARCHFLAGS` for anything older.

## In

The primitives : wake_swim, wake_plumtree, wake_dgram, wake_pheromone,
wake_quorum, wake_tac, wake_signal, wake_entity, wake_crypto ; unit
tests, libFuzzer targets for every untrusted-input surface (peer
datagrams, signed signals, a crafted pheromone or TAC file), and
ASan/UBSan/TSan runs.

## Not in

A network stack, a config format, cluster bootstrap/discovery
beyond the seed list a caller supplies, and any single global correlator:
`wake_tac` is intentionally per-instance and bounded, not a distributed
graph database.

## Must

- One write set. If the task needs a file outside it, stop.
- 4 spaces, K&R braces, snake_case, no VLA, bounded string APIs,
  check every allocation.
- Paste the command and its output. Do not claim tests passed without
  that paste.
- Format version and SONAME are frozen. Bumping them is a human
  decision (`Contract: abi|format|wire`).

## Never

- `git commit`, `git push`, `git tag`, `git rebase`, merge, force-push
- Rewrite `docs/COMMIT.md`, `.githooks/`, `scripts/check-commit-msg.sh`,
  `.github/workflows/`, or `CODEOWNERS` unless that is the write set
- Assistant attribution in comments, commits, or docs
- Em-dashes in anything that ships
