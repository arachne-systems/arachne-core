> Handoff brief H7. Updated 2026-09-26.

# H7: Final integration and cleanup

## BLUF

The lead merged H1, H2, H3, H4 and H6 locally. H7 qualifies their combined Core
in `codex/night-h7-integration`, based on `ad31b97`, then imports the final
follow-ups from `integrate/wave1`. The owner decides any merge to `main` or
outward action.

## Initial integrated evidence

The fresh all-target/all-feature test build passed. The first 118-executable
run had 687 passed, 2 failed and 21 ignored. A three-member convergence case
and a first-post-restart admission timing check failed. Unchanged focused
reruns passed; the first failures remain in the
[H7 report](../../evidence/h7-night-2026-09-26.md). H1 owns the deterministic
membership-driver starvation fix. Do not treat retries as the final green run.

## Work

- [x] Run the combined baseline and retain every result.
- [x] Confirm H1, H2, H3, H4 and H6 integration ancestry; H5 has its own SDK proof.
- [ ] Import and qualify the final H1 and general retained-tail follow-ups.
- [ ] Finish A3h dependency removal and workspace qualification.
- [ ] Run `cargo fmt --all` as its own commit after the code follow-ups merge.
- [ ] Pass `cargo clippy --workspace --all-targets --all-features -- -D warnings`;
  document each narrow lint exception.
- [ ] Pass the final full suite and dependency policy check.
- [x] Update Context, storage, candidates, events, deadlines and suspend/resume
  guidance in the integration guide, security guide and root README.
- [ ] Record final evidence and commits in the tracker. Keep unproved consumer
  and owner gates open.
- [ ] Finish the [owner merge summary](../h7-owner-merge-summary.md).
- [ ] Clean this lane's rebuildable target after its last check.

## Done when

The final source has recorded checks, each defect has evidence or an explicit
open status, and the owner can decide H8. No test receipt substitutes for an
existing-data upgrade, final SDK pin check or ATAK host qualification.
