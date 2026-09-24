# Architecture review work tracker (2026-09-24)

Source: [architecture review](2026-09-24-architecture-review.md). Tick each box only after its
test is red → green and the crate tests pass.

## Fix-now bugs (core)

- [x] **B1** (`b192cef`; legacy authority v1, kill switch and `issue_invitation` op removed) New workspaces default to legacy invitations (no expiry, revoke or use limit).
  Decision: remove the legacy mode entirely. No legacy workspaces, no compatibility path.
- [x] **B2** (`b192cef`; approvals single-use, consumed by the admission commit) A removed member can rejoin with the old approved request.
- [x] **B3** (`fix/sec-mgmt-bound` d226107) Receivers reject management commits above ~250 members (64 KiB inline bound).
- [x] **B3a** (`82f35c5`, `778dc1c`; checkpoint = tree-less pin + tree bound by tree hash, paged fetch; runtime join at 641 members over real Iroh passes; joiner limit now set by B3c) Joiners cannot receive an invitation above 241 members (64 KiB wire checkpoint carries the full ratchet tree). Needs a smaller joiner checkpoint (wire change).
- [x] **B3b** (`85ba181`; own history rebuilt under the local 8 MiB bound) A member restored with `join_history == None` still uses the inline bound and can reject a valid management commit above ~250 members.
- [ ] **B3c** (in `feat/a2-security-wiring` analysis) Management commits (link registration, Remove, Promote) are capped at 64 KiB (`bootstrap` `MAX_BYTES`). At ~82 B/member (the update path encrypts to every unmerged batch-added leaf), registration fails above ~785 members (769 = 64,006 B; 897 fails). Raising the cap alone fails: commits also travel as JSON history steps in one 128 KiB control reply, and DFMO offers are 32 KiB. Options: page history steps as binary; merge unmerged leaves (member SelfUpdate, A2 step 5) so the update path shrinks.
- [x] **B4** (`b192cef`; disabled rows pruned; 221 *active* links remains the cap, with a clear error) Invitation controls fill at 221 rows and are never pruned.
- [x] **B5** (`7dc9201`, workspace tests 387 pass / 0 fail) `stage_protected_publication` does not send `workspace`; a mismatch leaves the session stuck.
- [x] **B6** (`3236e4f`, workspace tests 387 pass / 0 fail) `create_endpoint` holds the global `REGISTRY` lock during bind (up to 10 s).
- [x] **B7** (`7984237`, workspace tests 387 pass / 0 fail) Automatic recovery never shrinks the range; large payloads can never catch up.
- [x] **B7b** (`ecbdc01`; verified signed range, admit longest prefix under quota, progress only that far; new `AwaitingApplication` state) Recovery stages a whole range, but A6 caps pending objects at 32 KiB per author, so runtime recovery of large payloads stops again (`fix/b7b-recovery-quota`, in progress).
- [ ] **B7c** `stage_direct_range` is still all-or-nothing under the per-author quota (in progress).
- [ ] **T1** Flake: `admission_staging` `admission_batch_staging_keeps_committing_under_continuous_intake` "node shutdown timed out" under load (`fix/flake-admission-staging`, in progress).
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

## SDK-facing notes from core changes

- B3a: a host that passes the checkpoint inline in `begin_join` JSON hits the 128 KiB request cap near 120 members. SDK must use the compact path (invitation link + peers).
- B3a: only the issuer, or a member whose join history starts at that checkpoint, can answer a join (narrower failover).
- A3: ops removed `stage_publication`, `stage_reception`, `enable_object_delivery`, `poll_recovered_publication`; added `poll_pending_object`, `stage_object_acknowledgement`, `stage_object_rejection`.
- B7b: new recovery state `recovery_awaiting_application`, field `accepted_through`; `RecoveryStage::AwaitingApplication`.
- B1: `issue_invitation` removed; use `stage_invitation` + `adopt_invitation`.
- A7r: `ClientConfig` gains relay, public lookup and timeouts.

## Architecture work (needs design first)

- [ ] **A1** — step 1 done (`arachne-api`, `71cc9db`); UniFFI spike running.
  Original: One typed, versioned contract; stable error codes; `#[non_exhaustive]`; consider UniFFI.
- [ ] **A2** — steps 1, 7 done (`b995fba`, `624c658`); ADR corrected. Wiring steps 2–6, 8–13 open.
  Original: Commit-ordering authority. **Decision open:** sequencer admin vs deterministic tie-break (recommended).
- [x] **A3** (`fix/a3-delivery-epochs`, merging)
  - [ ] A3f: runtime recovery ops (`fetch_recovery_range`, `discover_recovery_cutoff`) still ask for the current epoch only; wire the 4-epoch window.
  - [ ] A3g: check that a large workspace plus a full attachment fits the store's 1 MiB record limit.
  - [ ] A3h: drop unused `serde_json` in `arachne-delivery`; run `cargo fmt` workspace-wide once branches settle.
  Original: Decouple delivery and routing from the exact epoch and policy revision.
- [ ] **A4** Owned `Context`, event stream, `wait_for_work(timeout)`, `close(&self)`, suspend/resume.
- [ ] **A5** One persistence mode behind a `Storage` trait; schema versions and migrations.
- [x] **A6** (`fix/a3-delivery-epochs`; `docs/delivery.md`)
  Original: Delivery spec; per-author quotas; bitmap dedup; remove the legacy receive stack.
- [x] **A7** (`fix/a7-network`, merged)
  - [x] A7r (`79adbe4`, merged): runtime wiring — members-only gossip tag key, revision window in runtime checks and `real_node_lifecycle` test, one-behind `Message.revision`, `NodeOptions` into `create_endpoint`, stranger error kind Gate the data plane at handshake; fix metadata leaks; relay config; `Link` trait.
- [x] **A8** (`1b481ca`; per-namespace object key + namespace in AAD; true isolation still needs separate groups, documented)
  Original: Per-app or per-topic isolation.
- [x] **A9** Version ranges; renamed forks with own versions; SPDX license field. (`fix/a9-supply-chain`, merged into `integrate/wave1`)
  - [x] A9a (`fd189aa`; 40 comments rewritten, `docs/architecture.md` gossip section): ~40 `.rs` comments cite ADR 0008/0009/0010 that live only in `arachne-development`. Replace with inline rationale.
  - [x] A9b (`fix/a9b-tor`; torut replaced, deny clean): `tor` feature pulls `torut` → `ed25519-dalek 1.0.1` / `curve25519-dalek 3.2.0` (RUSTSEC-2022-0093, RUSTSEC-2024-0344).
  - [~] A9c: rusqlite 0.40.2 (SQLite 3.53.2) and getrandom 0.4 done (`a227d9a`). **Next** (after A3/B3a merge): our crates to sha2 0.11 + hkdf/hmac 0.13 (same as iroh 1.2 and openmls_rust_crypto 0.6; sha2 0.10 stays only via ed25519-dalek 2 / p256 / p384). **Keep** aes-gcm 0.10 (openmls_rust_crypto uses 0.10). Check sframe 2.0 separately.
  - [x] A9d (`334ab7f`): in-file change notices in fork sources; stale `release = false` in `release-plz.toml`.
  - [x] A9f (`8fcf5f8`, live Tor SAFECOOKIE passed): Tor control client uses plain COOKIE auth; add SAFECOOKIE. Full `tor_transport` node test not run (no Tor network reach here).
  - [ ] A9e (owner approval): publish `arachne-bao-tree`, then blobs, gossip, node, runtime; decide on yanking old fork versions.
- [ ] **A10** Split `arachne-runtime/src/lib.rs` by subsystem; test through the typed Client.
- [x] Fix stale docs (A9 `bbb5488`, A9a `fd189aa`) (`docs/integration.md` gaps list, missing ADR 0008/0009).
