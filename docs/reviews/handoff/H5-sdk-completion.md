> Written by Claude (AI). Handoff brief H5.

# H5: SDK — finish generated bindings, remove hand bindings, Android and ATAK

## BLUF

The SDK now generates Kotlin, Swift, Python and Go from one Rust module (UniFFI 0.31.2).
A two-client flow passes in all four languages, and an Android AAR builds with 16 KB pages.
What is left: storage and management in the generated surface, deleting the old hand bindings,
re-pinning core, CI, and the ATAK check.

## Start here

- SDK repo branch `feat/uniffi-sdk`, worktree `~/development/worktrees/arachne-sdk-uniffi` (18 commits on top of `fix/b10-b11-locks-pin`).
- The `core` submodule points at local-only core commit `2205887` (from `integrate/wave1`). CI cannot fetch it until core is pushed (H8).
- **Never edit `~/arachne-sdk`.** Another agent works there (Kotlin PR #1, branch `feat/kotlin-sdk`, live edits to `docs/android-consumer-plan.md`).
- Read: SDK `docs/language-bindings.md`; core `docs/reviews/adr-a1-a4-sdk-contract.md` (steps 7–9) and the "SDK-facing notes" and "SDK work" sections in the tracker.

## Done so far (SDK)

| Commit(s) | What |
| --- | --- |
| `3ebd82a`, `d528df4` (branch `fix/b10-b11-locks-pin`) | B11 core bump; B10 lock fix in Go/Python/Swift (RED/GREEN in all three) |
| `9be02b1`, `77ce461` | Core pin to `2205887`; Rust examples and tests ported; hand-binding CI steps disabled (`if: false`, TODO) |
| `8238762`..`20a1b54` | UniFFI scaffolding, patched Go generator (`patches/`), `scripts/generate-bindings.sh`, committed `generated/`, smoke tests, CI job `generated-bindings` with drift check |
| `98d2d9b`..`14ede3c` | Exported surface: invitation, join, admission, publication, inbox, recovery, presence, policy, deadlines, suspend/resume; two-client flow tests in four languages |
| `05f69b1`..`8a546d4` | Android AAR (arm64-v8a, x86_64, 16 KB aligned), R8 rules proven, CI job `generated-android` |

## Remaining work

- [ ] Re-pin `core` to the final `integrate/wave1` after H1, H2 and H4 merge. Regenerate. Fix breakage.
- [ ] Export storage and candidates using H2's new API (record storage, save/restore, discard, `drive_join`, `drive_workspace`).
- [ ] Export management, leave and revocation using H1's API.
- [ ] Remove every `// SHIM: remove after core step 6` once H4 lands (11 markers).
- [ ] Nearby (not exported yet).
- [ ] Delete `ffi.rs`, `include/arachne_sdk.h` and the hand Go/Python/Swift bindings (ADR step 8). Delete the disabled CI steps.
- [ ] Reconcile with Kotlin PR #1 (`feat/kotlin-sdk`, owned by another agent): the generated Kotlin replaces the hand Kotlin client. Keep its ideas (client-bound candidates, waiting outside the lock). Agree the merge order with the owner.
- [ ] ATAK host check (ADR step 9): does the ATAK host already ship JNA (`libjnidispatch.so`)? JNA is a POM dependency, not bundled in the AAR. Needs the owner's tablet rig; follow the rig reset rule (fresh reset before every test run).
- [ ] 16 KB page emulator test runs only in CI (no 16 KB image here).
- [ ] New host-visible states since the last pin (see tracker "SDK-facing notes"): `recovery_awaiting_application`, `direct_recovery_awaiting_application`, `missing_count`, `administrator_required`, self-update states, `close_drain`, C-ABI deadline functions.

## Known limits

- `request_admission` and `poll_membership_update` are not exported (untyped JSON) until H4.
- Go returns `**T` for optional objects.
- Flow tests call `suspend`/`resume` on the shared default context: a small flake risk.

## Done when

- Generated bindings cover the full typed Client. No hand bindings remain.
- `cargo test -p arachne-sdk --all-targets`, `scripts/uniffi-smoke.sh` and the Android AAR build pass.
- CI is green after core is pushed (H8).
