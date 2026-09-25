> Written by Claude (AI). Handoff brief H2.

# H2: A5 storage — one persistence mode, candidates, record ceiling

## BLUF

Items 1–7 of A5 are committed on `feat/a5-storage`. The branch then merged `integrate/wave1`
(which holds the A2 runtime work). That merge is committed as WIP and was never built. Two new
needs arrived after the merge: the 1 MiB record ceiling near 900 members, and branch records for H1.

## Start here

- Branch `feat/a5-storage`, worktree `~/development/worktrees/arachne-core-a5-storage`.
- Finished commits (on top of `integrate/wave1` before the A2 runtime merge):
  - `356b4d5` native record storage is the one persistence mode (items 1, 3)
  - `19a1368` typed candidates bound to kind, client and one use (item 2)
  - `eaded6e` storage root separate from the endpoint secret (item 4)
  - `008ba51` format versions, migration hook, atomic store creation (item 5)
  - `582dfba` freshness anchor required with monotonic storage (item 6, B9)
  - `3a1f08f` values above 512 KiB saved as parts; record bounds proven (item 7, A3g)
  - `dbd0791`, `51805b1`, `6c5458b` tests and fixes
- WIP merge commit `0119662`: merge of `integrate/wave1` (A2 runtime). **Not built, not tested.**
- First action: build all targets under the lock, fix compile errors from the merge, then run the storage and runtime tests.

## Read first

- `docs/reviews/2026-09-24-architecture-review.md` (A5, B9), `docs/reviews/adr-a1-a4-sdk-contract.md` (step 5).
- `crates/arachne-runtime/src/persistence.rs`, `ops/candidate.rs`, `crates/arachne-store`.
- The A2 runtime merge touched `ops/candidate.rs` (Management pattern, SelfUpdate arms) and `ops/workspace.rs` (endpoint signer, discard reset).

## Remaining work (test first, one commit each)

- [ ] Finish the merge: the workspace builds; storage and runtime tests pass.
- [ ] **Record ceiling.** At 900 members the OpenMLS provider/tree record is 1,367,294 bytes, over the 1 MiB record limit ("record exceeds byte budget"). Commit `3a1f08f` already saves values over 512 KiB as parts — check whether that covers the provider record. Target at least 2,000 members. Prove it with a release-mode test that is ignored by default.
- [ ] **Branch records for H1** (`runtime/branch/meta`, `runtime/branch/snapshot/<epoch>`): include them in `active_records()` / `commit_candidate()`; let `restore()` accept the `runtime/branch/` prefix.
- [ ] Check the joiner 2 MiB total-history cap against the same bounds (shared with H1).
- [ ] Write the breaking Client/JSON API changes for the SDK (H5). The storage and candidate API changed completely.

## Done when

- `integrate/wave1` + this branch builds with all targets and features.
- `cargo test -p arachne-store` and `-p arachne-runtime` pass.
- A workspace of at least 2,000 members stores and restores (release test).
- H1's branch records round-trip through save and restore.
