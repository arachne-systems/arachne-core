# Core and SDK integration: owner merge summary

## BLUF

H1–H6 are implemented and merged locally. H7 passes on Core `05434f86`:
706 tests passed, zero failed and 21 were ignored. Strict lint, Rust 1.91,
dependency and format checks pass. This lane removed its 12.0 GiB build cache.
No branch has been pushed or published. Existing tablet data is not yet
qualified for the new storage format.

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
H5's SDK checkpoint `3c750fb` passed four generated language flows and Android
packaging on Core `e420a52`. That result does not replace a final SDK pin check
or the existing-data device upgrade gate.

Final test source is `05434f86f4297b33620502dc3385f31953ff5889`. Strict Clippy,
Rust 1.91 workspace/default-feature compilation, dependency policy and format
checks pass. The final 120-executable run is uninterrupted: 706 passed, zero
failed and 21 ignored. The report retains the earlier 687/2/21 and 701/1/21
runs separately from the corrected run. H7 documentation follows the frozen
source; it does not change production code.
