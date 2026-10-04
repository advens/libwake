# Releasing

How to cut a libwake release: bump the version, update the changelog,
merge, tag, and let CI publish it. Tagging is the only step a human has
to do by hand; everything after the tag is automated.

## 1. Decide the version

`MAJOR.MINOR.PATCH`. The release tag and the SONAME (`libwake.so.<MAJOR>`)
move together (`README.md`, "Versioning"):

- The C ABI breaks (`Contract: abi`: exported layout, signature, or
  SONAME) -> bump MAJOR.
- New, backward-compatible API -> bump MINOR.
- Bug fixes only -> bump PATCH.

`Contract: format` and `Contract: wire` move `WAKE_PHT_VERSION`,
`WAKE_TAC_VERSION`, `WAKE_DGRAM_VERSION`, or `WAKE_SIGNAL_VERSION`.
Those constants do not move the SONAME. See `README.md`.

## 2. Bump the Makefile version

`LIB_MAJOR`, `LIB_MINOR`, `LIB_PATCH` at the top of `Makefile` are the
actual source of truth for the SONAME and for `wake.pc`'s `Version:`.
The git tag does not drive them; edit them by hand to match the tag you
are about to push. If MAJOR changes, the built `.so`/`.dylib` name and
`pkg-config`'s `-lwake` consumers all move with it, so this is itself a
`Contract: abi` change.

## 3. Update the changelog

Add a `## [MAJOR.MINOR.PATCH] - YYYY-MM-DD` section to `CHANGELOG.md`
(move relevant `[Unreleased]` entries into it, or write new ones),
following [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Update the links at the bottom:

```
[Unreleased]: https://github.com/advens/libwake/compare/MAJOR.MINOR.PATCH...HEAD
[MAJOR.MINOR.PATCH]: https://github.com/advens/libwake/releases/tag/MAJOR.MINOR.PATCH
```

This section is not optional decoration: the release workflow's release
notes are this section's text, verbatim.

## 4. PR it, merge to main

Same as any other change: a work branch, commits that each pass
`scripts/check-commit-msg.sh`, `Contract: abi` (or `format`/`wire`) on
whichever commit actually touches that surface, CI green, then merge.

## 5. Tag and push

```
git tag MAJOR.MINOR.PATCH
git push origin MAJOR.MINOR.PATCH
```

The tag must match `[0-9]+.[0-9]+.[0-9]+` exactly
(`.github/workflows/release.yml`'s trigger) and should point at a commit
already on `main`. Tags are not rewritten (`docs/BRANCHES.md`).

## What happens automatically

Pushing the tag fires `.github/workflows/release.yml`:

1. `make test` run against the tagged commit.
2. `git archive --format=tar.gz --prefix=libwake-<tag>/` produces the
   source tarball; a `.sha256` of it is computed alongside.
3. The `## [<tag>]` section of `CHANGELOG.md` is extracted as the
   release notes body (falls back to "See CHANGELOG.md." if that
   heading is missing, which is why step 3 above is not optional).
4. A GitHub Release named `<tag>` is published with both files attached.

No local packaging step, no manual upload: the tag push is the only
trigger.

## Verifying a release

```
gh release download <tag>
sha256sum -c libwake-<tag>.tar.gz.sha256
tar xzf libwake-<tag>.tar.gz
cd libwake-<tag> && make test
```
