> Handoff brief H7. Updated 2026-09-26.

# H7: Final integration and cleanup

## BLUF

The first H7 qualification on `05434f86` passed all gates. The deadline
follow-up on `2b568922` passes 710 tests, zero failed and 21 ignored across
120 executables. Counter source `7f99bfa` compiles and formats. Finish the
stream follow-ups before repeating the final strict checks. The first
12.0 GiB target was cleaned; the current target stays warm at the lead's
request. The owner decides any merge to `main` or outward action.

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

- [ ] Complete the later stream follow-ups, repeat final qualification and
  clean the new target after the lead ends the investigation.

## Done when

The final source has recorded checks, each defect has evidence or an explicit
open status, and the owner can decide H8. No test receipt substitutes for an
existing-data upgrade, final SDK pin check or ATAK host qualification.
