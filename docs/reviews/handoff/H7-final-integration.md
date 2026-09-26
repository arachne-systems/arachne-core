> Handoff brief H7. Updated 2026-09-26.

# H7: Final integration and cleanup

## BLUF

H7 is complete on final source `05434f86`: 706 tests passed, zero failed and
21 were ignored across 120 executables. Strict Clippy, Rust 1.91 workspace
compilation, dependency policy and formatting pass. This lane cleaned its
12.0 GiB target. The owner decides any merge to `main` or outward action.

## Initial integrated evidence

The fresh all-target/all-feature test build passed. The first 118-executable
run had 687 passed, 2 failed and 21 ignored. A three-member convergence case
and a first-post-restart admission timing check failed. Unchanged focused
reruns passed; the first failures remain in the
[H7 report](../../evidence/h7-night-2026-09-26.md). H1 fixed deterministic
membership-driver starvation. A later 701/1/21 run found an admission fixture
race, corrected in `911ecce`. Both failed runs remain separate from the final
uninterrupted 706/0/21 run.

## Work

- [x] Run the combined baseline and retain every result.
- [x] Confirm H1, H2, H3, H4 and H6 integration ancestry; H5 has its own SDK proof.
- [x] Import the final H1, retained-tail, MoQ and typed publication follow-ups.
- [x] Finish A3h dependency removal and workspace lint qualification.
- [x] Run `cargo fmt --all` as its own commit after the code follow-ups merge (`70b8c75`).
- [x] Pass `cargo clippy --workspace --all-targets --all-features -- -D warnings`;
  document each narrow lint exception.
- [x] Pass the final full suite and dependency policy check.
- [x] Update Context, storage, candidates, events, deadlines and suspend/resume
  guidance in the integration guide, security guide and root README.
- [x] Record final evidence and commits in the tracker. Keep unproved consumer
  and owner gates open.
- [x] Finish the [owner merge summary](../h7-owner-merge-summary.md).
- [x] Clean this lane's rebuildable target after its last check.

## Done when

The final source has recorded checks, each defect has evidence or an explicit
open status, and the owner can decide H8. No test receipt substitutes for an
existing-data upgrade, final SDK pin check or ATAK host qualification.
