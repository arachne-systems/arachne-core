# Core and SDK integration: owner merge summary

## BLUF

H1–H6 are implemented and merged locally. H7 is qualifying the combined Core
and fixing the defects found by that check. No branch has been pushed or
published by this lane. Existing tablet data is not yet qualified for the new
storage format.

## What changed

- Core owns a typed API, native errors, runtime Contexts and UniFFI metadata.
  The SDK generates language bindings and packages the native library.
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
| ATAK host | Qualify the single native library/session owner and JNA host path on the required host. An AAR build alone does not prove that path. |
| External actions | The owner decides pushes, registry publication, fork yanks and the generator contribution in H8. |

## Evidence

The [H7 report](../evidence/h7-night-2026-09-26.md) keeps the initial integrated
RED, unchanged repetitions, fixes, final checks and their source revisions.
The [tracker](2026-09-24-work-tracker.md) links each earlier package's proof.
H5's SDK checkpoint `3c750fb` passed four generated language flows and Android
packaging on Core `e420a52`. That result does not replace a final SDK pin check
or the existing-data device upgrade gate.

Final H7 totals and commit hashes remain pending until the checks finish.
