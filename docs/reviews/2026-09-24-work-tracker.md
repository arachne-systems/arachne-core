# Architecture review work tracker (2026-09-24)

Source: [architecture review](2026-09-24-architecture-review.md). Tick each box only after its
test is red → green and the crate tests pass.

## Fix-now bugs (core)

- [ ] **B1** New workspaces default to legacy invitations (no expiry, revoke or use limit).
  Decision: remove the legacy mode entirely. No legacy workspaces, no compatibility path.
- [ ] **B2** A removed member can rejoin with the old approved request.
- [ ] **B3** Receivers reject management commits above ~250 members (64 KiB inline bound).
- [ ] **B4** Invitation controls fill at 221 rows and are never pruned.
- [ ] **B5** `stage_protected_publication` does not send `workspace`; a mismatch leaves the session stuck.
- [ ] **B6** `create_endpoint` holds the global `REGISTRY` lock during bind (up to 10 s).
- [ ] **B7** Automatic recovery never shrinks the range; large payloads can never catch up.
- [ ] **B8** The latest-value index never prunes and fills for good.
- [ ] **B9** The freshness anchor is not wired into restore (rollback → state replay, SFrame counter reuse).

## SDK bugs (arachne-sdk repo — owned by the SDK agent, not this branch)

- [ ] **B10** Go, Python and Swift hold the client lock in `wait_for_work`; `close()` deadlocks.
- [ ] **B11** The SDK pins core 7123166, which is missing `fbc4e91` (wake host loop after delivery).

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

- [ ] **A1** One typed, versioned contract; stable error codes; `#[non_exhaustive]`; consider UniFFI.
- [ ] **A2** Commit-ordering authority. **Decision open:** sequencer admin vs deterministic tie-break (recommended).
- [ ] **A3** Decouple delivery and routing from the exact epoch and policy revision.
- [ ] **A4** Owned `Context`, event stream, `wait_for_work(timeout)`, `close(&self)`, suspend/resume.
- [ ] **A5** One persistence mode behind a `Storage` trait; schema versions and migrations.
- [ ] **A6** Delivery spec; per-author quotas; bitmap dedup; remove the legacy receive stack.
- [ ] **A7** Gate the data plane at handshake; fix metadata leaks; relay config; `Link` trait.
- [ ] **A8** Per-app or per-topic isolation.
- [ ] **A9** Version ranges; renamed forks with own versions; SPDX license field.
- [ ] **A10** Split `arachne-runtime/src/lib.rs` by subsystem; test through the typed Client.
- [ ] Fix stale docs (`docs/integration.md` gaps list, missing ADR 0008/0009).
