# Architecture review work tracker (2026-09-24)

Source: [architecture review](2026-09-24-architecture-review.md). Tick each box only after its
test is red → green and the crate tests pass.

## BLUF

H1, H2, H3, H4 and H6 are merged locally on `integrate/wave1`. Core has API
version 6, native storage, opaque candidates, generated binding metadata and
bounded fork recovery. H5 proves the generated SDK on Core `e420a52`. H7 now
checks the combined Core branch. Owner decisions and unproved consumer upgrades
stay open below.

## Integration evidence (2026-09-26)

| Package | Implementation and merge | Evidence |
| --- | --- | --- |
| H1 | `3379267`, `5a80e43`; merges `3ab4486`, `0808c38` | [Fork and proof-transfer report](../evidence/h1-night-2026-09-26.md) |
| H2 | `840c25a`; merge `0d5e071` | [Native storage report](../evidence/h2-night-2026-09-26.md) |
| H3 | `a6619db`; merge `688946b` | [Measured test profile](handoff/H3-test-speed.md) |
| H4 | `91ce5b1`; merge `e420a52` | [Core binding report](../evidence/h4-night-2026-09-26.md) |
| H5 (SDK) | SDK `3c750fb`, Core `e420a52` | Four language flows, Rust, AAR, R8 and Android test APK passed; device/ATAK gates remain |
| H6 | `fc06673`; merge `ad31b97` | [Crypto report](../evidence/h6-night-2026-09-26.md): 681 passed, 0 failed, 20 ignored; MSRV and deny green |
| H7 | `codex/night-h7-integration`, base `ad31b97` | Initial RED retained; H1 driver fix imported; strict Clippy, deny and MSRV green; format `70b8c75`; final suite pending |

The H6 total includes 18 tests in 20 example harnesses. It is a corrected
aggregate with the original failures and reruns retained in its receipts.
The SDK report is `docs/reviews/2026-09-26-h5-sdk-completion.md` in the SDK repo.

Open gates: migrate remaining Core dispatcher callers; choose and reconcile the
SDK line; prove the existing-data upgrade; qualify the ATAK host; approve pushes
and publication. The [H8 brief](handoff/H8-owner-decisions.md) owns outward actions.

## H7 integration defects

- [x] Same-epoch convergence (`21054c4`, integration `94e30da`): baseline `ad31b97` kept one of three members on a
  different authenticated branch for the full 20-second deadline. The unchanged
  test then passed three focused runs and three complete-binary runs. H1
  reproduced native driver starvation, fixed it, and passed deterministic
  checks plus 50 unchanged convergence runs. The first RED stays in the H7
  evidence. The combined run on `70b8c75` passed the returning-member binary.
- Admission timing: the first post-restore intake measured 1.909802 ms against
  an early median of 0.93733 ms (2.038 times). Three unchanged runs passed the
  existing two-times bound. The fixture is unchanged from H6; its correctness,
  negative authorization and performance assertions remain intact. It also
  passed in the combined run on `70b8c75`.
- [x] Admission push fixture (`911ecce`): local task cancellation did not prove
  remote exchange expiry. The test now waits for the owner's observed expiry
  within the same deadline and requires zero old-exchange replies and one
  push. Fifty corrected exact repeats and all 13 admission tests passed.
  The original combined run remains 701 passed, one failed and 21 ignored;
  the corrected full run is reported separately in the H7 evidence.

## Fix-now bugs (core)

- [x] **B1** (`b192cef`; legacy authority v1, kill switch and `issue_invitation` op removed) New workspaces default to legacy invitations (no expiry, revoke or use limit).
  Decision: remove the legacy mode entirely. No legacy workspaces, no compatibility path.
- [x] **B2** (`b192cef`; approvals single-use, consumed by the admission commit) A removed member can rejoin with the old approved request.
- [x] **B3** (`fix/sec-mgmt-bound` d226107) Receivers reject management commits above ~250 members (64 KiB inline bound).
- [x] **B3a** (`82f35c5`, `778dc1c`; checkpoint = tree-less pin + tree bound by tree hash, paged fetch; runtime join at 641 members over real Iroh passes; joiner limit now set by B3c) Joiners cannot receive an invitation above 241 members (64 KiB wire checkpoint carries the full ratchet tree). Needs a smaller joiner checkpoint (wire change).
- [x] **B3b** (`85ba181`; own history rebuilt under the local 8 MiB bound) A member restored with `join_history == None` still uses the inline bound and can reject a valid management commit above ~250 members.
- [x] **B3c** (`840c25a`, `5a80e43`; merges `0d5e071`, `0808c38`). Binary membership pages and physical record parts remove the old inline and 1 MiB logical-value failures. H2 saved 2,049 members, then restored a name change and member 2,050. H1 bounds large proof transfer over the existing Iroh control connection. The current count/byte limits remain explicit in the [security guide](../security.md#membership-proof-transfer-and-bounds).
- [x] **B4** (`b192cef`; disabled rows pruned; 221 *active* links remains the cap, with a clear error) Invitation controls fill at 221 rows and are never pruned.
- [x] **B5** (`7dc9201`, workspace tests 387 pass / 0 fail) `stage_protected_publication` does not send `workspace`; a mismatch leaves the session stuck.
- [x] **B6** (`3236e4f`, workspace tests 387 pass / 0 fail) `create_endpoint` holds the global `REGISTRY` lock during bind (up to 10 s).
- [x] **B7** (`7984237`, workspace tests 387 pass / 0 fail) Automatic recovery never shrinks the range; large payloads can never catch up.
- [x] **B7b** (`ecbdc01`; verified signed range, admit longest prefix under quota, progress only that far; new `AwaitingApplication` state) Recovery stages a whole range, but A6 caps pending objects at 32 KiB per author, so runtime recovery of large payloads stops again (`fix/b7b-recovery-quota`, in progress).
- [x] **B7c** (`ddb20d3`; direct prefix admission + stuck-gap exemption per author) `stage_direct_range` was all-or-nothing under the per-author quota.
- [x] **B7d** (`c6af1de`) Proved not reachable: receiver eviction opens gaps first (max 185 of 512 pending while all blocked). Guard test `direct_global_bound.rs`.
- [x] **B7e** (`eecd315`; eviction records misses as `missing_count`; late copies at/below floor dropped) Eviction moves the floor past a gap silently: the late object is delivered after newer ones and no miss is recorded (breaks `docs/delivery.md`). In progress.
- [x] **B7f** (`8272b66`, `518f328`): report `missing_count` on the adoption response too; count sequences skipped by `advance()` at epoch change as missed.
- [x] **B3d** (`2dbe0e2`) Admission history pages were size-checked before a 20-byte `history_page` field was added; ~1–2% of runs landed in the gap. Now each page is measured in final form. Sweep test over every fill point.
- [x] **T1** (`670f068`, `afd1b9a`) `admission_staging` flake: close drain waited 3×PTO (26 s under load) vs a fixed 5 s. Now a separate `close_drain` deadline (5 s, all profiles incl. Tor; host can override); drain finishes in background. Test `close_drain.rs`.
- [x] **B8** (`c142361`, workspace tests 387 pass / 0 fail) The latest-value index never prunes and fills for good.
- [x] **B9** (`71f8cfa`, workspace tests 387 pass / 0 fail) The freshness anchor is not wired into restore (rollback → state replay, SFrame counter reuse).

## SDK bugs (arachne-sdk repo — owned by the SDK agent, not this branch)

- [x] **B10** (SDK `fix/b10-b11-locks-pin` d528df4; Go/Python/Swift red→green) Go, Python and Swift hold the client lock in `wait_for_work`; `close()` deadlocks.
- [x] **B11** (SDK `fix/b10-b11-locks-pin` 3ebd82a; core → b06a72d) The SDK pins core 7123166, which is missing `fbc4e91` (wake host loop after delivery).

## ATAK plugin → SDK readiness (from `arachne-sdk/docs/android-consumer-plan.md`)

The plugin reaches Core through `fabric-android` today; the SDK has its own native entry point
and a different Core pin. Core work that each plan step depends on:

| Plan step | Core dependency |
| --- | --- |
| 1. One Core revision, one native library and session owner | B11 (pin); A4 (owned `Context`, no static registry, no per-cdylib runtimes) |
| 2. Typed SDK methods for ATAK workflows | A1: add typed methods in core `Client` (management, invitations, workspace name, presence, nearby, seal/restore), not in Kotlin |
| 3. Candidate safety through Rust and the C boundary | A5 (typed candidate handles that carry their kind, one persistence mode), B5 |
| 4. Distinct ID types, error categories through the C ABI | A1: core must emit real error codes first; today `ErrorKind` is a substring guess |
| 5. End-to-end flow through the AAR, then ATAK host | B9 (freshness anchor), A4 (suspend/resume, `wait_for_work(timeout)`) |

## SDK work

- [x] SDK B10/B11 (`fix/b10-b11-locks-pin`).
- [x] UniFFI pipeline (`feat/uniffi-sdk`, 9 commits): generated Kotlin/Swift/Python/Go, committed `generated/` + drift check in CI, patched Go generator, smoke tests pass in all four; Rust examples/tests ported to new core; hand-binding CI steps disabled (to be deleted).
- [x] Extend generated Client groups (Core `91ce5b1`, SDK `3c750fb`): 95 Client methods plus Context, storage, candidates, admission, management, current/direct/range recovery and resources.
- [x] Core step 6 binding blockers (Core `91ce5b1`): Core-owned UniFFI derives, stable IDs/errors/network enum, `Event::ALL`, fixed-width counts, typed driver results and opaque received proofs. Four generated language flows pass in H5.
- [x] Delete SDK `ffi.rs`, C header and hand bindings (SDK `3c750fb`). The SDK no longer copies Core domain or persistence logic.
- [ ] Reconcile the live Kotlin branch and select the SDK line. The owner decides. H5's default SDK build still needs the PTT line's `moq` feature forwarding before streaming calls are available.

## SDK-facing notes from core changes

- B3a: a host that passes the checkpoint inline in `begin_join` JSON hits the 128 KiB request cap near 120 members. SDK must use the compact path (invitation link + peers).
- B3a: only the issuer, or a member whose join history starts at that checkpoint, can answer a join (narrower failover).
- A3: ops removed `stage_publication`, `stage_reception`, `enable_object_delivery`, `poll_recovered_publication`; added `poll_pending_object`, `stage_object_acknowledgement`, `stage_object_rejection`.
- A2/H2 runtime: self-update stages, saves and adopts locally before it announces committed history. `drive_workspace` reports `self_update_committed` and typed branch outcomes. Recovery activity can report `branch_orphaned` or `branch_send_quarantined`; a current roster alone is not send readiness. Membership proofs can use bounded Iroh fragments (H1).
- A4b: C-ABI `set_deadline(handle, ms)`, `create_with_deadline(secret, options, ms)`; `TransportOptions::deadline`.
- A4: `Context`, `ContextConfig`, `Limits`, `PowerProfile`, `Client::open_in`, `wait_for_work(Option<Duration>)`, `wake`, `next_event`, `set_deadline`/`with_deadline`, `suspend`/`resume`; C-ABI handle fns `wait_for_work_timeout`, `wake`, `next_event`; `close` idempotent; `API_VERSION` 6 (H4).
- T1: `TransportTimeouts` gains `close_drain` (breaking for struct literals).
- B7c: new state `direct_recovery_awaiting_application`.
- B7b: new recovery state `recovery_awaiting_application`, field `accepted_through`; `RecoveryStage::AwaitingApplication`.
- B1: `issue_invitation` removed; use `stage_invitation` + `adopt_invitation`.
- A7r: `ClientConfig` gains relay, public lookup and timeouts.
- A5/H2: storage is supplied before create/join; adoption owns commit and read-back;
  candidate objects replace snapshot tokens in the typed API. See
  [SDK migration](h2-storage-sdk-migration.md). H4 sets `API_VERSION` to 6.

## Architecture work (needs design first)

- [~] **A1** — Core and SDK steps 1–8 are implemented (`91ce5b1`; SDK `3c750fb`). One Core-owned typed contract, native errors, feature gates and generated metadata are proved through four language flows. Step 9 remains: migrate the existing Core dispatcher/qualification callers and complete the ATAK single-library host path before deleting that dispatcher. See [binding and upgrade gates](h4-core-sdk-migration.md#fixtures-and-json-removal).
  Original: One typed, versioned contract; stable error codes; `#[non_exhaustive]`; consider UniFFI.
- [x] **A2** — steps 1–13 implemented (`3379267`, `5a80e43`; merges `3ab4486`, `0808c38`). Deterministic commit classes/hash order, endpoint-signed credentials, admin-only admission, durable self-update, branch switch, revocation carry, local re-publication and bounded settlement are wired. The H1 report records RED/GREEN and convergence proofs. Public-anchor follow-up is tracked separately by H1.
  Original: Commit-ordering authority. Decision made: deterministic tie-break; removal and leave have highest priority.
- [x] **A3** (`fix/a3-delivery-epochs`, merging)
  - [x] A3f (`8078d8e`): runtime recovery ops (`fetch_recovery_range`, `discover_recovery_cutoff`) still ask for the current epoch only; wire the 4-epoch window.
  - [x] A3g (H2): 2,049 members save as parts, then a name change and one admission
    restore with 2,050 members. Fixed attachment bounds fit. A 3,208,876-byte H1
    snapshot restores from seven parts. See [evidence](../evidence/h2-night-2026-09-26.md).
  - [x] A3h (`381f451`, `70b8c75`): unused `serde_json` edge removed with static RED/GREEN. Strict all-feature Clippy and the separate workspace formatting check pass. Final integrated execution is recorded in the H7 row.
  Original: Decouple delivery and routing from the exact epoch and policy revision.
- [x] **A4** (`feat/a4-context` merged at `2205887`; full suite before merge 526 pass / 0 fail; ADR steps 3–4; default limits 64 sessions / 320 overlay paths accepted)
  - [x] A4c (`6b98b22`, `5db52d3`): 8 leftover test locks removed; `cargo test -p arachne-runtime` runs with default threads (39 binaries pass).
  - [x] A4b (`f0eb382`..`b419723`; suspend closes idle links + stops mDNS via wrapper; Low ×4 all timers; deadlines on bind/policy/send + C-ABI `set_deadline`; 5 event e2e tests). Was: mDNS has no pause API (iroh-mdns-address-lookup 0.5); suspend does not close idle connections; Low profile only slows presence; deadlines only on typed Client and only for outbound control exchanges; end-to-end event tests for MembershipChanged, ProtectedReceived, RecoveryReady, CurrentViewReady, Presence.
  Original: Owned `Context`, event stream, `wait_for_work(timeout)`, `close(&self)`, suspend/resume.
- [x] **A5** (`840c25a`; merged `0d5e071`): native storage, typed candidates, separate storage root, format versions, anchors and large-value parts. H1 branch records share the atomic commit. The package store/runtime suite had 243 passed and zero failed; integrated focused checks and the H6 full suite passed. See [evidence](../evidence/h2-night-2026-09-26.md) and [SDK migration](h2-storage-sdk-migration.md). Deployment to older app data still needs the authenticated upgrade proof.
- [x] **A6** (`fix/a3-delivery-epochs`; `docs/delivery.md`)
  Original: Delivery spec; per-author quotas; bitmap dedup; remove the legacy receive stack.
- [x] **A7** (`fix/a7-network`, merged)
  - [x] A7r (`79adbe4`, merged): runtime wiring — members-only gossip tag key, revision window in runtime checks and `real_node_lifecycle` test, one-behind `Message.revision`, `NodeOptions` into `create_endpoint`, stranger error kind Gate the data plane at handshake; fix metadata leaks; relay config; `Link` trait.
- [x] **A8** (`1b481ca`; per-namespace object key + namespace in AAD; true isolation still needs separate groups, documented)
  Original: Per-app or per-topic isolation.
- [x] **A9** Version ranges; renamed forks with own versions; SPDX license field. (`fix/a9-supply-chain`, merged into `integrate/wave1`)
  - [x] A9a (`fd189aa`; 40 comments rewritten, `docs/architecture.md` gossip section): ~40 `.rs` comments cite ADR 0008/0009/0010 that live only in `arachne-development`. Replace with inline rationale.
  - [x] A9b (`fix/a9b-tor`; torut replaced, deny clean): `tor` feature pulls `torut` → `ed25519-dalek 1.0.1` / `curve25519-dalek 3.2.0` (RUSTSEC-2022-0093, RUSTSEC-2024-0344).
  - [x] A9c (`fc06673`; merged `ad31b97`): all nine owned old-generation edges now use SHA-2 0.11 and HKDF/HMAC 0.13. SFrame 2.0 uses ring; AES-GCM stays 0.10. MSRV 1.91 and cargo-deny pass. Upstream elliptic-curve/dalek still require three duplicate names; the lead accepted that explicit scope limit. No dependency or duplicate version was added. See [H6 evidence](../evidence/h6-night-2026-09-26.md).
  - [x] A9d (`334ab7f`): in-file change notices in fork sources; stale `release = false` in `release-plz.toml`.
  - [x] A9f (`8fcf5f8`, live Tor SAFECOOKIE passed): Tor control client uses plain COOKIE auth; add SAFECOOKIE. Full `tor_transport` node test not run (no Tor network reach here).
  - [ ] A9e (owner approval): publish `arachne-bao-tree`, then blobs, gossip, node, runtime; decide on yanking old fork versions.
- [x] **A10** (`feat/a1-typed-ops` merged; lib.rs 8k → 163 lines, 14 ops modules) Split `arachne-runtime/src/lib.rs` by subsystem. Typed Client tests are present; migration of the remaining dispatcher callers is the open A1 step 9 gate.
- [x] Fix stale docs (A9 `bbb5488`, A9a `fd189aa`) (`docs/integration.md` gaps list, missing ADR 0008/0009).
