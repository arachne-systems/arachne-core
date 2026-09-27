> Handoff package for the Arachne Core and SDK remediation. Updated 2026-09-26.

# Handoff: Arachne Core and SDK remediation

## BLUF

H1, H2, H3, H4 and H6 are merged locally on `integrate/wave1`. H7 source
`6c70a6d` passes 726 tests, zero failed and 22 ignored across 120 executables.
All strict gates pass. H5 SDK `7057bd6` passes fresh Rust and Python checks on
this Core source; other language and Android proofs keep their earlier pins.
Both completed H7 targets were cleaned. H8 and consumer upgrade gates need
owner decisions.
The [work tracker](../2026-09-24-work-tracker.md) separates implementation
evidence from these open gates.

## Where the work is

| Item | Location |
| --- | --- |
| Review (findings) | `docs/reviews/2026-09-24-architecture-review.md` |
| Tracker (status of every finding) | `docs/reviews/2026-09-24-work-tracker.md` |
| Design decisions | `docs/reviews/adr-a1-a4-sdk-contract.md`, `docs/reviews/adr-a2-commit-ordering.md`, `docs/reviews/spike-a1-uniffi.md` |
| Delivery spec | `docs/delivery.md` (on `integrate/wave1`) |
| Review docs branch | `review/core-architecture` is retained; its documents are in the integration worktree |
| Integration branch (all merged work) | `integrate/wave1`, worktree `~/development/worktrees/arachne-core-integrate`, H7 base `ad31b97`; later checkpoints are in the work tracker |
| Core repo | `https://github.com/arachne-systems/arachne-core` (local worktrees under `~/development/worktrees/arachne-core-*`) |
| SDK repo | `https://github.com/arachne-systems/arachne-sdk` (worktrees `~/development/worktrees/arachne-sdk-*`) |

Nothing is pushed. All branches are local.

## Work package status

| ID | Package | Branch (worktree) | State | Depends on |
| --- | --- | --- | --- | --- |
| [H1](H1-a2-fork-healing.md) | A2 fork healing, revocation carry, re-publication and settlement | `codex/night-h1-forks` and follow-ups | `3379267` and fragment checkpoint `5a80e43` merged; public anchors `08d021a` and scheduler `21054c4` merged; included in final H7 qualification | — |
| [H2](H2-a5-storage.md) | Native storage, opaque candidates, physical parts, branch records | `codex/night-h2-storage` | `840c25a` merged as `0d5e071`; old-data upgrade is a release gate | — |
| [H3](H3-test-speed.md) | Optimize dependencies in test builds | `a6619db` | merged as `688946b`; same-source before/after measurements are in `docs/development.md` | — |
| [H4](H4-core-ffi-api.md) | Core-owned typed API and UniFFI metadata | `codex/night-h2-storage` | `91ce5b1` merged as `e420a52`; dispatcher caller migration remains open | H2 |
| [H5](H5-sdk-completion.md) | Generated bindings and Android packaging | SDK `codex/night-h5-refresh` | Final `7057bd6` / Core `6c70a6d`: fresh Rust, examples and Python pass; 15 generated hashes unchanged. Four-language proof stays `2183cb3` / Core `0d37ba9`. Android `853bacd` / Core `05434f86` was not rebuilt. MoQ is opt-in; default AAR excludes it. SDK-line/ATAK decisions open | H1, H2, H4 |
| [H6](H6-crypto-dependency-bumps.md) | SHA-2 0.11, HKDF/HMAC 0.13 and SFrame check | `codex/night-h6-crypto` | `fc06673` merged as `ad31b97`; MSRV, deny and corrected full suite green | H1, H2 |
| [H7](H7-final-integration.md) | Integrated qualification, cleanup and merge summary | `codex/night-h7-integration` | final `6c70a6d`: 726/0/22 and all strict gates green; prior REDs and 706/0/21, 710/0/21, 724/0/22 remain separate. First 12.0 GiB and final 7.9 GiB targets cleaned; current target absent | all |
| [H8](H8-owner-decisions.md) | Owner decisions and outward actions | — | open | — |

## Rules every agent must follow

1. **CPU and memory.** The owner's machine overheated with parallel builds.
   - Build only under the shared lock: `flock ~/development/worktrees/.cargo-build.lock nice -n 19 env CARGO_BUILD_JOBS=4 cargo +1.98.0 test --locked -p <crate> --no-run`.
   - Run tests OUTSIDE the lock, pinned to 4 CPUs: `nice -n 19 taskset -c <4 cpus> <test binary> <filter>`. Give each agent different CPUs.
   - Never share `CARGO_TARGET_DIR` between worktrees. Artifacts leak across branches.
   - One cargo command at a time per agent. No stress loops.
   - Run slow large-member tests once, at the end, in release mode.
2. **Disk.** Each worktree `target/` grows to 20–140 GB. Delete `target/` of finished worktrees.
3. **Test-driven.** Write the failing test first, capture the RED line, then fix, then capture GREEN. Report both lines.
4. **No legacy modes.** Remove old paths and add no compatibility shims. A wire or storage change still needs an authenticated upgrade proof before deployment over existing app data. Keep device data.
5. **Scope.** Stay in the files your brief names. When a shared file must change, keep the hunk small and say so in the report.
6. **Outward actions** (push, publish, public GitHub activity) need the owner's approval. See H8.
7. **Toolchain.** Rust `1.98.0` (MSRV `1.91`). Swift 6.1.3 via `source ~/.local/share/swiftly/env.sh`. Android NDK at `~/Android/Sdk/ndk/27.1.12297006`, `cargo-ndk` installed. Python via `uv`.

## How to merge a finished package

The lead agent owns the integration worktree. Package agents report their tested
commit and leave that worktree unchanged.

1. In `~/development/worktrees/arachne-core-integrate`: `git merge --no-edit <branch>`.
2. Build all targets under the lock: `cargo check --locked --workspace --all-targets --all-features`.
3. Build tests with `--workspace --all-targets --all-features --no-run` under the lock. Run each reported test executable outside the lock, pinned to the assigned four CPUs. The H7 lane uses CPUs 4–7 and four test threads. Record each exit status and retain the first failure.
4. Record the source commit, features, binary count, totals, ignored tests and any reruns in the tracker. Do not report a corrected aggregate as an uninterrupted green run.
