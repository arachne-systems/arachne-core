# Architecture review work tracker (2026-09-24)

Source: [architecture review](2026-09-24-architecture-review.md). Tick each box only after its
test is red → green and the crate tests pass.

## PAUSED 2026-09-24 ~21:50 (weekly usage limit) — resume notes

- Integration branch: `integrate/wave1` at `bc2a2d1` (worktree `arachne-core-integrate`). Last full suite before A2-runtime merge: 526 pass / 0 fail. Post-merge full suite was stopped at 26 pass / 0 fail — rerun first.
- In flight (agents stopped; work on disk, not lost):
  - `feat/a2-forks` (A2 steps 8–13): 16 commits ahead + 7 uncommitted files. Was starting the delivery re-publish step.
  - `feat/a5-storage` (A5 + A3g + 1 MiB record ceiling + A2 branch-record needs): 10 commits ahead, **merge of integrate/wave1 in progress** with 76 uncommitted files. Finish or `git merge --abort` first.
  - `feat/a4-context` test-speed task (dep opt-level): 1 uncommitted file (Cargo.toml profile experiment), nothing committed.
- SDK: `feat/uniffi-sdk` (arachne-sdk worktree `arachne-sdk-uniffi`): pipeline + stable surface + Android AAR done; waits on A5 (storage) and A2 (management). Core submodule pinned to local-only `2205887`.
- Rules: build under `flock <worktrees>/.cargo-build.lock ... --no-run`, run tests outside the lock pinned (`taskset`), nice 19, 4 jobs; clean finished `target/` dirs (disk fills fast).
- Needs owner OK: push branches, crates.io publish (A9e), upstream Go generator patch.

## Fix-now bugs (core)

- [x] **B1** (`b192cef`; legacy authority v1, kill switch and `issue_invitation` op removed) New workspaces default to legacy invitations (no expiry, revoke or use limit).
  Decision: remove the legacy mode entirely. No legacy workspaces, no compatibility path.
- [x] **B2** (`b192cef`; approvals single-use, consumed by the admission commit) A removed member can rejoin with the old approved request.
- [x] **B3** (`fix/sec-mgmt-bound` d226107) Receivers reject management commits above ~250 members (64 KiB inline bound).
- [x] **B3a** (`82f35c5`, `778dc1c`; checkpoint = tree-less pin + tree bound by tree hash, paged fetch; runtime join at 641 members over real Iroh passes; joiner limit now set by B3c) Joiners cannot receive an invitation above 241 members (64 KiB wire checkpoint carries the full ratchet tree). Needs a smaller joiner checkpoint (wire change).
- [x] **B3b** (`85ba181`; own history rebuilt under the local 8 MiB bound) A member restored with `join_history == None` still uses the inline bound and can reject a valid management commit above ~250 members.
- [~] **B3c** Commit size fixed (self-update: 12 KB at 900 members; 96 KiB bound; binary paged transport). **Remaining:** OpenMLS tree record 1.37 MB at 900 members > 1 MiB store record limit → assigned to A5. (Was: in `feat/a2-security-wiring` analysis; runtime side also: binary history steps instead of JSON number arrays (~3.6 chars/byte); page the no-pinned-checkpoint admission reply path) Management commits (link registration, Remove, Promote) are capped at 64 KiB (`bootstrap` `MAX_BYTES`). At ~82 B/member (the update path encrypts to every unmerged batch-added leaf), registration fails above ~785 members (769 = 64,006 B; 897 fails). Raising the cap alone fails: commits also travel as JSON history steps in one 128 KiB control reply, and DFMO offers are 32 KiB. Options: page history steps as binary; merge unmerged leaves (member SelfUpdate, A2 step 5) so the update path shrinks.
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
- [ ] Extend generated surface to stable Client groups (in progress); storage/candidates after A5; management/revocation after A2.
- [ ] Core step 6 blockers from the SDK: `#[non_exhaustive]` blocks remote derives (add `uniffi` derives behind a feature in arachne-api); `Event` needs `ALL`; `[u8;32]` IDs, `usize`, `serde_json::Value` returns (`drive_join`, `request_admission`, `drive_workspace`, `poll_membership_update`), `&[&str]`, `&Path`; `with_deadline(self)`; two `Network` enums (Tor feature-gated); plain struct error; `open_in(&Arc<Context>)`; close-race code 101 vs `Closed`.
- [ ] Delete `ffi.rs` + hand bindings; reconcile Kotlin PR #1 (other agent's) with generated Kotlin.

## SDK-facing notes from core changes

- B3a: a host that passes the checkpoint inline in `begin_join` JSON hits the 128 KiB request cap near 120 members. SDK must use the compact path (invitation link + peers).
- B3a: only the issuer, or a member whose join history starts at that checkpoint, can answer a join (narrower failover).
- A3: ops removed `stage_publication`, `stage_reception`, `enable_object_delivery`, `poll_recovered_publication`; added `poll_pending_object`, `stage_object_acknowledgement`, `stage_object_rejection`.
- A2 runtime: host step JSON is `{step: <binary>, kind, invitation_checkpoint?}`; network admission reply has no top-level `commit`; new reason `administrator_required`; states `self_update_offered|pending|committed|refused`, `membership_offer_pull`; `Client::members_without_self_update()`; self-update only runs in native `drive_workspace`.
- A4b: C-ABI `set_deadline(handle, ms)`, `create_with_deadline(secret, options, ms)`; `TransportOptions::deadline`.
- A4: `Context`, `ContextConfig`, `Limits`, `PowerProfile`, `Client::open_in`, `wait_for_work(Option<Duration>)`, `wake`, `next_event`, `set_deadline`/`with_deadline`, `suspend`/`resume`; C-ABI handle fns `wait_for_work_timeout`, `wake`, `next_event`; `close` idempotent; `API_VERSION` 5.
- T1: `TransportTimeouts` gains `close_drain` (breaking for struct literals).
- B7c: new state `direct_recovery_awaiting_application`.
- B7b: new recovery state `recovery_awaiting_application`, field `accepted_through`; `RecoveryStage::AwaitingApplication`.
- B1: `issue_invitation` removed; use `stage_invitation` + `adopt_invitation`.
- A7r: `ClientConfig` gains relay, public lookup and timeouts.

## Architecture work (needs design first)

- [ ] **A1** — steps 1–2 done (`71cc9db`, `feat/a1-typed-ops` → `bfd10cc`); UniFFI spike done. Next: A4 (steps 3–4), A5 (step 5) in progress; then steps 6–9.
  Original: One typed, versioned contract; stable error codes; `#[non_exhaustive]`; consider UniFFI.
- [ ] **A2** — steps 1–7 done and runtime integrated (`feat/a2-security-wiring`, `feat/a2-runtime` merged at `60e14c9`: binary paged steps, digest offers, 96 KiB commit bound, self-update policy, admin-only admission). Steps 8–13 (fork detection/switch, order carry-forward, re-publish, settlement, convergence tests, docs) in progress on `feat/a2-forks`.
  Original: Commit-ordering authority. **Decision open:** sequencer admin vs deterministic tie-break (recommended).
- [x] **A3** (`fix/a3-delivery-epochs`, merging)
  - [x] A3f (`8078d8e`): runtime recovery ops (`fetch_recovery_range`, `discover_recovery_cutoff`) still ask for the current epoch only; wire the 4-epoch window.
  - [ ] A3g: check that a large workspace plus a full attachment fits the store's 1 MiB record limit.
  - [ ] A3h: drop unused `serde_json` in `arachne-delivery`; run `cargo fmt` workspace-wide once branches settle.
  Original: Decouple delivery and routing from the exact epoch and policy revision.
- [x] **A4** (`feat/a4-context` merged at `2205887`; full suite before merge 526 pass / 0 fail; ADR steps 3–4; default limits 64 sessions / 320 overlay paths accepted)
  - [x] A4c (`6b98b22`, `5db52d3`): 8 leftover test locks removed; `cargo test -p arachne-runtime` runs with default threads (39 binaries pass).
  - [x] A4b (`f0eb382`..`b419723`; suspend closes idle links + stops mDNS via wrapper; Low ×4 all timers; deadlines on bind/policy/send + C-ABI `set_deadline`; 5 event e2e tests). Was: mDNS has no pause API (iroh-mdns-address-lookup 0.5); suspend does not close idle connections; Low profile only slows presence; deadlines only on typed Client and only for outbound control exchanges; end-to-end event tests for MembershipChanged, ProtectedReceived, RecoveryReady, CurrentViewReady, Presence.
  Original: Owned `Context`, event stream, `wait_for_work(timeout)`, `close(&self)`, suspend/resume.
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
- [x] **A10** (`feat/a1-typed-ops` merged; lib.rs 8k → 163 lines, 14 ops modules) Split `arachne-runtime/src/lib.rs` by subsystem; test through the typed Client.
- [x] Fix stale docs (A9 `bbb5488`, A9a `fd189aa`) (`docs/integration.md` gaps list, missing ADR 0008/0009).
