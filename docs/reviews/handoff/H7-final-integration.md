> Handoff brief H7. Updated 2026-09-26.

# H7: Final integration and cleanup

## BLUF

Final H7 source `0d37ba9` passes 724 tests, zero failed and 22 ignored across
120 executables. Strict Clippy, Rust 1.91 workspace/default-feature compilation,
dependency policy, format and local documentation links pass. Earlier REDs and
qualified runs stay separate in the report. The first 12.0 GiB target was cleaned;
the current 7.8 GiB target stays warm until the lead's 08:30 CDT decision.
The owner decides any merge to `main` or outward action.

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
- [x] Clean this lane's first qualification target (12.0 GiB).

- [x] Complete the later stream follow-ups and repeat full and strict qualification
  on frozen source `0d37ba9` (724/0/22).
- [ ] Clean the new target after the lead ends the warm-cache hold and all owned
  build/test processes have exited. The next decision is at 08:30 CDT.

## Done when

The final source has recorded checks, each defect has evidence or an explicit
open status, and the owner can decide H8. No test receipt substitutes for an
existing-data upgrade, final SDK pin check or ATAK host qualification.
