# Commit message contract

Every commit in this repository uses this shape. No exceptions: not
the first commit, not a typo fix, not a revert. The hook and CI
reject anything else. GitHub squash-merge uses the PR title as the
subject and the PR body as the rest; those must match this contract
too.

## Shape

```
<type>(<scope>): <subject>

Why:
<one or more lines: the reason the tree changes>

Proof:
<command plus its decisive output, or "not run: <reason>">

Contract: none | abi | format | wire
```

One blank line after the subject. No extra headers. `Signed-off-by:`
is allowed after `Contract:`. Nothing else.

## First line

- `<type>` is one of: `feat` `fix` `perf` `refactor` `test` `build`
  `ci` `docs` `chore`
- `<scope>` is one of: `tac` `swim` `dgram` `crypto` `entity`
  `quorum` `pheromone` `signal` `plumtree` `fuzz` `build` `github`
  `docs`
- `<subject>` is imperative, ASCII, no trailing period, no em-dash
- The whole first line is at most 72 characters
- The first line is the only summary. Do not repeat it in Why.

## Why

What problem this commit solves, or what invariant it restores. Not
a file list. Not "update X". If you cannot write Why, the change is
not a commit yet.

## Proof

Paste the acceptance command and the lines that prove the claim. If
the command was not run, the line is `not run: <reason>`. "not run"
without a reason is invalid. Silence is not proof.

## Contract

Which frozen surface this commit touches:

| Value | Surface |
|-------|---------|
| `none` | No exported header, SONAME, file format, or datagram change |
| `abi` | Exported headers, SONAME, `pkg-config` |
| `format` | Pheromone table (`WAKE_PHT_VERSION`) or TAC table (`WAKE_TAC_VERSION`) |
| `wire` | SWIM/PlumTree datagram (`WAKE_DGRAM_VERSION`) or mesh signal (`WAKE_SIGNAL_VERSION`) |

`abi`, `format`, and `wire` need a human merge owner who read the
diff. They are not drive-by changes. File and datagram versions do
not follow the SONAME. See `README.md`, "Versioning".

## Forbidden in any line

- Tool or assistant attribution (`Co-Authored-By` for an assistant,
  "Generated with", product names of coding agents)
- Em-dash (U+2014) and double-hyphen used as a prose dash
- Trailing subject period
- A type or scope not in the lists above
- An empty Why or Proof section

## Local enforcement

```
git config core.hooksPath .githooks
git config commit.template .gitmessage
```

`scripts/check-commit-msg.sh <file>` is what the hook and CI run.
A commit whose message this script rejects does not enter `main`.
