> Written by Claude (AI). Handoff brief H1.

# H1: A2 steps 8–13 — fork detection, branch switch, settlement

## BLUF

Two admins can commit at the same epoch and split the group. Steps 1–7 of ADR A2 are done and merged
(fork key, branch snapshots, admin-only Adds, codec v3, revocation orders, member self-update,
endpoint binding, binary paged transport). Steps 8–13 make the group detect a split and converge
on one branch. Work started; one untested WIP commit exists.

## Start here

- Branch `feat/a2-forks`, worktree `~/development/worktrees/arachne-core-a2-forks`, base `integrate/wave1` at `bc2a2d1`.
- WIP commit `df5dcec` (481 lines, NOT built, NOT tested):
  - `crates/arachne-security/src/branch_steps.rs` (new, 179 lines) and additions to `branch.rs`.
  - `crates/arachne-delivery/src/publisher.rs`, `inbox.rs`, `lib.rs`: start of re-publish from a losing branch.
  - `crates/arachne-delivery/tests/branch_switch.rs` (new test).
- First action: build it. Keep what is sound. Split it into proper commits with RED/GREEN evidence.

## Read first

1. `docs/reviews/adr-a2-commit-ordering.md` — all of it, including both "Corrections" sections and "B3c measurements". The corrections override the earlier text.
2. `crates/arachne-security/src/fork.rs`, `branch.rs` (steps 1 and 7).
3. Revocation order API: `RevocationOrder`, `OrderStep`, `AnchorProof`, `prepare_revocation`, `verify_step`, `prepare_step_update`.
4. Runtime: `crates/arachne-runtime/src/membership.rs` and `membership/` (head gossip, `membership_branch_mismatch`).

## Steps to do (one commit each, test first)

- [ ] **8. Detect and switch.** `BranchQuery` / `BranchReply` and a head-gossip version bump. Compute the fork key locally from verified steps; never trust a peer's class. Load the `BranchState` snapshot at the fork point, check `epoch() == fork_epoch`, replay the winning steps through stage → save → adopt. No snapshot → orphaned state → admin re-add.
- [ ] **9. Carry revocation orders.** Gossip orders across branches; commit carried orders on the winning branch; stop sending (keep receiving) while an order that affects this node waits.
- [ ] **10. Re-publish.** Re-encrypt and re-send own objects from the losing branch under the winning epoch (the WIP started this). Retry own lost actions.
- [ ] **11. Settlement.** Epoch E settles when every member of E reports E+1 or later. Removed members never report, so those epochs settle by the window.
- [ ] **12. Convergence tests.** ADR tests T1–T13 and T8b, deterministic, no real network where possible. Must include: two admins commit at one epoch; partition with a Remove on one side, then heal; the removed member is excluded after convergence; a seeded property test.
- [ ] **13. Docs.** `docs/security.md`: fork choice, settlement, the real window (about 24 epochs for large snapshots), trust assumptions.

Also fix:
- [ ] Race: the only admin's own self-update against a Leave that a member commits.
- [ ] Race: two admins commit competing steps at one epoch (covered by step 12).
- [ ] `MAX_RUNTIME_ADMISSION_BATCH = 16`: its comment is about JSON arrays, which are gone. Measure with binary steps and set a sound value.
- [ ] Joiner total history cap is 2 MiB (about 17 maximum-size steps). Make it consistent with the B3c bounds and paging.

## Storage (coordinate with H2)

Branch state must be stored in the encrypted record store:
- `runtime/branch/meta`: first_unsettled, orphaned flag, retained epochs, carried orders.
- `runtime/branch/snapshot/<u64 BE epoch>`: one sealed security-only workspace per epoch, ≤ ~790 KiB, at most 64, total ≤ 16 MiB.
- H2 must: include the staged candidate's branch records in `active_records()` / `commit_candidate()`, and let `restore()` accept the `runtime/branch/` prefix and pass it to `membership::fork::restore`.
- Until H2 lands, use in-memory state plus the smallest possible `persistence.rs` hook, and list the diff.

## Done when

- Every step above has a commit with RED and GREEN evidence.
- The convergence tests pass. A removed member never regains access after a heal.
- `cargo test -p arachne-security`, `-p arachne-delivery` and `-p arachne-runtime` pass (runtime runs with default threads).
- Report lists wire changes and Client/JSON changes for the SDK (H5).
