# Core and SDK integration: owner merge summary

## BLUF

Core H1, H2, H3, H4 and H6 are merged locally; H5 has a separate SDK proof.
The H7 deadline follow-up on `2b568922` passes 710 tests, with zero failures
and 21 ignored. The earlier `05434f86` passed all strict checks. New receive
counters on `7f99bfa` compile. Final qualification waits for the stream fixes.
Keep the current target warm; the first 12.0 GiB cache was removed. No branch
has been pushed or published. Existing tablet data is not yet qualified for
the new storage format.

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
H5's SDK checkpoint `0d857b7` refreshed all 15 generated files and passed four
language flows and Android packaging on Core `05434f86`. Its `moq` feature
forwards to Core. The default AAR excludes streaming support. These results
do not replace the final SDK pin check or the existing-data device upgrade gate.

The first qualified test source is `05434f86f4297b33620502dc3385f31953ff5889`. Strict Clippy,
Rust 1.91 workspace/default-feature compilation, dependency policy and format
checks pass. The final 120-executable run is uninterrupted: 706 passed, zero
failed and 21 ignored. The report retains the earlier 687/2/21 and 701/1/21
runs separately from the corrected run. The deadline follow-up adds an uninterrupted 710/0/21 result on `2b568922`.
The counter follow-up has compile and format evidence only; a final full
qualification will follow the remaining stream work.
