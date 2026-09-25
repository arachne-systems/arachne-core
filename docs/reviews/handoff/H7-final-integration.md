> Written by Claude (AI). Handoff brief H7.

# H7: Final integration and cleanup

## BLUF

`integrate/wave1` holds all merged work. After H1–H6, this package cleans up, runs the full suite
once, and prepares the branch for review and merge to `main`.

## State of `integrate/wave1`

- Head `bc2a2d1`.
- Last green full suite: 526 passed, 0 failed, 15 ignored (before the A2 runtime merge).
- After the A2 runtime merge: the build passes, delivery tests pass, but the full suite was stopped at 26 passed, 0 failed. **Rerun it first.**

## Work

- [ ] Rerun the full suite on `integrate/wave1` now (see README "How to merge").
- [ ] Merge H1, H2, H3, H4, H6 as each finishes. Full suite after each large merge.
- [ ] A3h: remove the unused `serde_json` dependency in `arachne-delivery`.
- [ ] Run `cargo fmt --all` once, as its own commit, after all branches are merged (many files are not rustfmt-clean; formatting earlier would cause conflicts).
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`: fix or document.
- [ ] Update `docs/integration.md`, `docs/security.md`, `README.md` for the new API (Context, storage, candidates, events, deadlines, suspend/resume).
- [ ] Tick every box in `docs/reviews/2026-09-24-work-tracker.md` with its commit.
- [ ] Write a short merge summary for the owner (what changed, breaking changes, test totals).

## Done when

- Every finding in the tracker is ticked with evidence.
- Full suite green, `cargo deny` green, clippy clean or documented.
- The owner has what they need to decide the push (H8).
