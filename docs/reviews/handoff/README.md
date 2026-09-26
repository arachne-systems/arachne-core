> Written by Claude (AI). Handoff package for the Arachne Core and SDK remediation. Status on 2026-09-24: paused.

# Handoff: Arachne Core and SDK remediation

## BLUF

Most findings are fixed, tested and merged on `integrate/wave1`. Eight work packages are open.
Each package below has its own brief. An agent can start any package from its brief alone.
Do packages H1 and H2 first. H4 and H5 depend on them.

## Where the work is

| Item | Location |
| --- | --- |
| Review (findings) | `docs/reviews/2026-09-24-architecture-review.md` |
| Tracker (status of every finding) | `docs/reviews/2026-09-24-work-tracker.md` |
| Design decisions | `docs/reviews/adr-a1-a4-sdk-contract.md`, `docs/reviews/adr-a2-commit-ordering.md`, `docs/reviews/spike-a1-uniffi.md` |
| Delivery spec | `docs/delivery.md` (on `integrate/wave1`) |
| Review docs branch | `review/core-architecture`, worktree `~/development/worktrees/arachne-core-arch-review` |
| Integration branch (all merged work) | `integrate/wave1`, worktree `~/development/worktrees/arachne-core-integrate`, head `bc2a2d1` |
| Core repo | `https://github.com/arachne-systems/arachne-core` (local worktrees under `~/development/worktrees/arachne-core-*`) |
| SDK repo | `https://github.com/arachne-systems/arachne-sdk` (worktrees `~/development/worktrees/arachne-sdk-*`) |

Nothing is pushed. All branches are local.

## Open work packages

| ID | Package | Branch (worktree) | State | Depends on |
| --- | --- | --- | --- | --- |
| [H1](H1-a2-fork-healing.md) | A2 steps 8–13: fork detection, branch switch, settlement | `feat/a2-forks` (`arachne-core-a2-forks`) | WIP commit `df5dcec`, not built | — |
| [H2](H2-a5-storage.md) | A5 storage: one mode, candidates, record ceiling, branch records | `feat/a5-storage` (`arachne-core-a5-storage`) | 9 commits + WIP merge `0119662`, not built after merge | — |
| [H3](H3-test-speed.md) | Test speed: optimize dependencies in test builds | `feat/a4-context` (`arachne-core-a4-context`) | WIP `f84acfe`, not measured | — |
| [H4](H4-core-ffi-api.md) | Core step 6: FFI-friendly typed API (SDK blockers) | new, from `integrate/wave1` | not started | H2 (client storage API) |
| [H5](H5-sdk-completion.md) | SDK: finish generated bindings, delete hand bindings, Android/ATAK | `feat/uniffi-sdk` (`arachne-sdk-uniffi`) | 18 commits, green | H1, H2, H4 |
| [H6](H6-crypto-dependency-bumps.md) | A9c: sha2 0.11, hkdf/hmac 0.13, sframe check | new, from `integrate/wave1` | not started | merge of H1/H2 (touches all crates) |
| [H7](H7-final-integration.md) | Final integration: cleanup, full suite, merge plan | `integrate/wave1` | ongoing | all |
| [H8](H8-owner-decisions.md) | Owner decisions and outward actions | — | waiting on owner | — |

## Rules every agent must follow

1. **CPU and memory.** The owner's machine overheated with parallel builds.
   - Build only under the shared lock: `flock ~/development/worktrees/.cargo-build.lock nice -n 19 env CARGO_BUILD_JOBS=4 cargo +1.98.0 test --locked -p <crate> --no-run`.
   - Run tests OUTSIDE the lock, pinned to 4 CPUs: `nice -n 19 taskset -c <4 cpus> <test binary> <filter>`. Give each agent different CPUs.
   - Never share `CARGO_TARGET_DIR` between worktrees. Artifacts leak across branches.
   - One cargo command at a time per agent. No stress loops.
   - Run slow large-member tests once, at the end, in release mode.
2. **Disk.** Each worktree `target/` grows to 20–140 GB. Delete `target/` of finished worktrees.
3. **Test-driven.** Write the failing test first, capture the RED line, then fix, then capture GREEN. Report both lines.
4. **No legacy modes.** Pre-release: change wire and storage formats freely. Delete old code paths. Add no compatibility shims.
5. **Scope.** Stay in the files your brief names. When a shared file must change, keep the hunk small and say so in the report.
6. **Outward actions** (push, publish, public GitHub activity) need the owner's approval. See H8.
7. **Toolchain.** Rust `1.98.0` (MSRV `1.91`). Swift 6.1.3 via `source ~/.local/share/swiftly/env.sh`. Android NDK at `~/Android/Sdk/ndk/27.1.12297006`, `cargo-ndk` installed. Python via `uv`.

## How to merge a finished package

1. In `~/development/worktrees/arachne-core-integrate`: `git merge --no-edit <branch>`.
2. Build all targets under the lock: `cargo check --locked --workspace --all-targets --all-features`.
3. Run the full suite outside the lock on CPUs 28–31 (takes about 1 hour): build with `--no-run` under the lock, then `nice -n 19 taskset -c 28-31 cargo +1.98.0 test --locked --workspace --no-fail-fast`.
4. Record the totals in the tracker. The last green full suite (before the A2 runtime merge) was 526 passed, 0 failed.
