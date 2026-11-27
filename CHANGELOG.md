# Changelog

## [Unreleased]

### Added

- `wake_prevmsg`: a signed prevalence batch for PlumTree. Up to ten rows
  of a keyed 64-bit hash, an event count and a source count, with the
  tenant, key id and window start, signed with the origin's Ed25519 key.
  The origin's public key is inside the signed bytes, so a relayed batch
  verifies and cannot be replayed under another node. 126 to 252 bytes,
  little-endian, versioned by `WAKE_PREVMSG_VERSION` = 1. Unit tests,
  ASan/UBSan run, and `fuzz_prevmsg` in `libfuzz-ci`.

## [0.3.1] - 2026-10-04

A pheromone claim keeps up to three packed reason words in the padding
of the 128-byte entry. The table version stays 1. An old file reads as
no reasons. The shared library file is libwake.so.0.3.1.

## [0.3.0] - 2026-09-23

First tagged release, packaged from the initial public tree plus a
pkgconfig install-path fix (lib/pkgconfig instead of FreeBSD-only
libdata/pkgconfig on non-FreeBSD platforms).

[Unreleased]: https://github.com/advens/libwake/compare/0.3.1...HEAD
[0.3.1]: https://github.com/advens/libwake/releases/tag/0.3.1
[0.3.0]: https://github.com/advens/libwake/releases/tag/0.3.0
