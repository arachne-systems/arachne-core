> Written by Claude (AI). Handoff brief H4.

# H4: Core step 6 — FFI-friendly typed API

## BLUF

The SDK exports core's typed `Client` through UniFFI. It works today only with SDK-side shims
(marked `// SHIM: remove after core step 6`). This package fixes the causes in core so the shims
can go. Start after H2 lands, because H2 rewrites the client's storage and candidate API.

## Start here

- New branch from `integrate/wave1` (after H2 is merged).
- Read `docs/reviews/adr-a1-a4-sdk-contract.md` (step 6, Implementation notes), `docs/reviews/spike-a1-uniffi.md`,
  and in the SDK repo `docs/language-bindings.md` and `crates/arachne-sdk/src/uniffi_api/` on `feat/uniffi-sdk`.

## Blockers found by the SDK work (each with proof in the SDK report)

- [x] `#[non_exhaustive]` types cannot be UniFFI remote types (E0004/E0639). Add UniFFI derives in `arachne-api` behind a `uniffi` feature.
- [x] `Event` has no `ALL` list, so a mirror cannot detect a new event at build time.
- [x] Types UniFFI cannot carry: `[u8; 32]` IDs (use the `arachne-api` ID newtypes), `usize` (use `u64`), `serde_json::Value` returns (`drive_join`, `request_admission`, `drive_workspace`, `poll_membership_update`), `&[&str]` (`install_member_policy`), `&Path` (`enable_record_storage`).
- [x] `request_admission` and `poll_membership_update` return a peer's raw JSON. Give them typed results.
- [x] Direct-recovery ops (`next_direct_gap`, `fetch_direct_recovery`, and the rest) exist only in the JSON dispatcher. Add them to the typed `Client`.
- [x] `with_deadline(self)` fails behind an `Arc` (E0507). Keep `set_deadline(&self)` as the main form.
- [x] Two `Network` enums: the runtime one has `Tor` only with the `tor` feature. Use one `Network` with `Tor` always present; return `Unsupported` when the feature is off.
- [x] Client methods return a plain struct error (`client::Error`). Return `ApiError`.
- [x] `open_in(&Arc<Context>)`: `Context` is not exported. Decide the export shape.
- [x] Close race: an op racing `close` gets code 101 (`InvalidId`) but `kind()` says `Closed`. Return `Closed` (code 1).
- [x] Mark `RecoveryStage` and other public enums `#[non_exhaustive]` where missing (B7b added a variant).
- [x] `Capabilities.limits` from the client's context (A4 note).

## Also in this package (ADR steps 6 and 9 prerequisites)

- [x] `capabilities()` op; fixtures (`install_verified_policy`, unprotected `publish`/`poll`, `pub mod harness`) behind a `test-fixtures` feature.
- [x] Plan the deletion of the JSON `execute` dispatcher (ADR step 9). It must stay until the SDK no longer calls it (H5).

## Done when

- Each blocker has a test that shows the typed API works without an SDK shim.
- The SDK branch builds after removing the matching shims (coordinate with H5).

## Implementation receipt

The H4 branch provides these exports from Core metadata. H5 reports passing generated
two-client flows in Kotlin, Swift, Python and Go on `8ce6498`, with the corresponding SDK
shims removed. See `../h4-core-sdk-migration.md` for the API changes and
`../../evidence/h4-night-2026-09-26.md` for the local test receipts and remaining release gates.
The final integrated SDK pin still needs its own generated-language checks.
