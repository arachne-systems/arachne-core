# Architecture review work tracker (2026-09-24)

Source: [architecture review](2026-09-24-architecture-review.md). Tick each box only after its
test is red → green and the crate tests pass.

## Fix-now bugs (core)

- [x] **B1** (`b192cef`; legacy authority v1, kill switch and `issue_invitation` op removed) New workspaces default to legacy invitations (no expiry, revoke or use limit).
  Decision: remove the legacy mode entirely. No legacy workspaces, no compatibility path.
- [x] **B2** (`b192cef`; approvals single-use, consumed by the admission commit) A removed member can rejoin with the old approved request.
- [x] **B3** (`fix/sec-mgmt-bound` d226107) Receivers reject management commits above ~250 members (64 KiB inline bound).
- [ ] **B3a** Joiners cannot receive an invitation above 241 members (64 KiB wire checkpoint carries the full ratchet tree). Needs a smaller joiner checkpoint (wire change).
- [ ] **B3b** A member restored with `join_history == None` still uses the inline bound and can reject a valid management commit above ~250 members.
- [x] **B4** (`b192cef`; disabled rows pruned; 221 *active* links remains the cap, with a clear error) Invitation controls fill at 221 rows and are never pruned.
- [x] **B5** (`7dc9201`, workspace tests 387 pass / 0 fail) `stage_protected_publication` does not send `workspace`; a mismatch leaves the session stuck.
- [x] **B6** (`3236e4f`, workspace tests 387 pass / 0 fail) `create_endpoint` holds the global `REGISTRY` lock during bind (up to 10 s).
- [x] **B7** (`7984237`, workspace tests 387 pass / 0 fail) Automatic recovery never shrinks the range; large payloads can never catch up.
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

## Architecture work (needs design first)

- [ ] **A1** — step 1 done (`arachne-api`, `71cc9db`); UniFFI spike running.
  Original: One typed, versioned contract; stable error codes; `#[non_exhaustive]`; consider UniFFI.
- [ ] **A2** — steps 1, 7 done (`b995fba`, `624c658`); ADR corrected. Wiring steps 2–6, 8–13 open.
  Original: Commit-ordering authority. **Decision open:** sequencer admin vs deterministic tie-break (recommended).
- [ ] **A3** Decouple delivery and routing from the exact epoch and policy revision.
- [ ] **A4** Owned `Context`, event stream, `wait_for_work(timeout)`, `close(&self)`, suspend/resume.
- [ ] **A5** One persistence mode behind a `Storage` trait; schema versions and migrations.
- [ ] **A6** Delivery spec; per-author quotas; bitmap dedup; remove the legacy receive stack.
- [x] **A7** (`fix/a7-network`, merged)
  - [x] A7r (`79adbe4`, merged): runtime wiring — members-only gossip tag key, revision window in runtime checks and `real_node_lifecycle` test, one-behind `Message.revision`, `NodeOptions` into `create_endpoint`, stranger error kind Gate the data plane at handshake; fix metadata leaks; relay config; `Link` trait.
- [ ] **A8** Per-app or per-topic isolation.
- [x] **A9** Version ranges; renamed forks with own versions; SPDX license field. (`fix/a9-supply-chain`, merged into `integrate/wave1`)
  - [ ] A9a: ~40 `.rs` comments cite ADR 0008/0009/0010 that live only in `arachne-development`. Replace with inline rationale.
  - [x] A9b (`fix/a9b-tor`; torut replaced, deny clean): `tor` feature pulls `torut` → `ed25519-dalek 1.0.1` / `curve25519-dalek 3.2.0` (RUSTSEC-2022-0093, RUSTSEC-2024-0344).
  - [ ] A9c: behind latest: sha2 0.11, aes-gcm 0.11, hkdf 0.13, sframe 2.0, rusqlite 0.40; getrandom 0.2 vs 0.4 split.
  - [x] A9d (`334ab7f`): in-file change notices in fork sources; stale `release = false` in `release-plz.toml`.
  - [x] A9f (`8fcf5f8`, live Tor SAFECOOKIE passed): Tor control client uses plain COOKIE auth; add SAFECOOKIE. Full `tor_transport` node test not run (no Tor network reach here).
  - [ ] A9e (owner approval): publish `arachne-bao-tree`, then blobs, gossip, node, runtime; decide on yanking old fork versions.
- [ ] **A10** Split `arachne-runtime/src/lib.rs` by subsystem; test through the typed Client.
- [ ] Fix stale docs (`docs/integration.md` gaps list, missing ADR 0008/0009).
