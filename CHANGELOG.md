# Changelog

## [Unreleased]

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
