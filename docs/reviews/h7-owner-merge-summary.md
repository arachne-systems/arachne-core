# Core and SDK integration: owner merge summary

## BLUF

Core H1, H2, H3, H4 and H6 are merged locally. Final H7 source `0d37ba9`
passes 724 tests, with zero failures and 22 ignored across 120 executables.
Strict Clippy, Rust 1.91 workspace/default-feature compilation, dependency
policy and formatting also pass. H5 host checks use the same Core source.
The first 12.0 GiB cache was removed; the current 7.8 GiB target stays warm
until the lead's 08:30 CDT decision. No branch has been pushed or published.
Existing tablet data is not yet qualified for the new storage format.

## What changed

- Core owns a typed API, native errors, runtime Contexts and UniFFI metadata.
  The SDK generates language bindings and packages the native library.
  Typed publication options expose native recipient bounds and Critical,
  Bulk or Current mode. Existing methods keep their default behavior.
- Core owns save, read-back and adoption. Typed candidates bind a staged change
  to one client and operation. Large logical records use bounded physical parts.
- Membership uses deterministic branch choice, authenticated proof transfer,
  bounded rollback retention, revocation carry, re-publication and settlement.
- General retained content can come from an authorized holder. The holder can
  differ from the author. Blobs resource transfers retain workspace and reader
  authorization. Retained-tail repair does not claim omitted history.
- LAN discovery and MoQ restart fixes remain in the integration branch. Crypto
  dependencies use the newer owned SHA-2/HKDF/HMAC generations. Test dependencies
  are optimized while Arachne code keeps debug checks.

## Breaking changes and remaining decisions

| Item | Required action |
| --- | --- |
| API version 6 | Consume Core's typed records, Context, errors and opaque candidate objects. Do not copy domain or persistence rules into an SDK wrapper. |
| Native storage | Supply a private directory and separate 32-byte storage root before create, join or restore. Keep the endpoint identity and protect both secrets. |
| Existing device state | Prove an authenticated atomic conversion of the old store and inbox. A path move is insufficient. Preserve authority, counters, retained data and crash recovery. |
| SDK line | The owner selects and reconciles the generated SDK and live Kotlin/PTT lines. Keep the streaming feature forwarding and repeat language/AAR checks on the selected final pin. |
| Dispatcher removal | Migrate the remaining Core qualification callers and ATAK consumer before deleting the old dispatcher. No second persistence mode is needed. |
| Current-value continuity | Holder recovery is proved at a fixed epoch. Automatic current-value re-publication after every normal epoch change remains open. |
| Concurrent default Context proof | The additive publication tests use owned Contexts. An earlier concurrent default-Context fixture reported a locally rejected connection; that observation remains open. |
| ATAK host | Qualify the single native library/session owner and JNA host path on the required host. An AAR build alone does not prove that path. |
| External actions | The owner decides pushes, registry publication, fork yanks and the generator contribution in H8. |

## Evidence

The [H7 report](../evidence/h7-night-2026-09-26.md) keeps the initial integrated
RED, unchanged repetitions, fixes, final checks and their source revisions.
The [tracker](2026-09-24-work-tracker.md) links each earlier package's proof.
H5's SDK checkpoint `2183cb3` passes four host language flows on Core `0d37ba9`.
All 15 generated files match fresh generation. Rust examples, default tests and
three opt-in MoQ metrics tests also pass. Its `moq` feature forwards to Core.
The preserved AAR, R8 and test APK use SDK `853bacd` / Core `05434f86`; this
refresh did not rebuild them. The default AAR excludes streaming support.
The selected mobile package still needs matching bindings, native code and
existing-data upgrade checks.

The final qualified implementation is `0d37ba9d73385278aa7baf34a3d831d991a0686e`.
Its uninterrupted full run has 724 passed, zero failed and 22 ignored across
120 executables. Strict Clippy, Rust 1.91 workspace/default-feature compilation,
dependency policy, format and 63 local documentation links pass. The group-read
fix has separate RED evidence and 40 unchanged focused repeat passes.

The report keeps the earlier 687/2/21 and 701/1/21 failed runs, first qualified
706/0/21 on `05434f86`, and deadline follow-up 710/0/21 on `2b568922` separate.
The new ignored case is a subprocess helper. A host proof does not close the
current tablet stall, selected mobile package, old-data upgrade or ATAK gates.
