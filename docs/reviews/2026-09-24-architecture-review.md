# Arachne Core architecture review (2026-09-24)

> Written by Claude (AI) from five parallel read-only reviews. Base: core `origin/main` b06a72d.
> SDK context: `arachne-sdk` `origin/main` (pins core 7123166) and `feat/kotlin-sdk`.

## BLUF

Core is careful at the byte level: bounded codecs, stage → commit → adopt, pure delivery
state machines. It is not yet a stable foundation for the SDK and many apps. Four areas
must change before the API freezes:

1. **Contract.** The real public API is an untyped, unversioned JSON dispatcher with string errors.
2. **Membership in a P2P network.** Nobody orders commits, and removal is weak.
3. **Epoch coupling.** Delivery and routing state reset on each membership change, which breaks DDIL use.
4. **Process globals.** A static registry, a cap of 8 sessions, and one Tokio runtime per client.

## Fix-now bugs (small, local, reproduced or verified)

| ID | Where | Problem | Evidence |
| --- | --- | --- | --- |
| B1 | security | New workspaces accept any admin-signed invitation forever (`legacy=true`). No expiry, no revoke, no use limit. | `lib.rs:199`, `invitation_controls.rs:116,167`; confirmed by code read |
| B2 | security | A removed member can rejoin with the same old approved request. | `invitation_controls.rs:163`; reviewer probe reproduced (not re-run) |
| B3 | security | Receivers reject management commits above ~250 members (64 KiB inline bound), while the admin advances. The result is a fork. | `management.rs:358`, `bootstrap.rs:476`; code path plus size measured by reviewer (no end-to-end receive run) |
| B4 | security | Invitation controls fill up at 221 rows and are never pruned. After that, no new invitations. | `invitation_controls.rs:85`; probe re-run: `invitations created before failure=221` |
| B5 | runtime | `stage_protected_publication` never sends `workspace`; a mismatch is found after staging and leaves the session stuck. | `client.rs:912-944` |
| B6 | runtime | `create_endpoint` holds the global `REGISTRY` lock for up to 10 s during bind; every other client stalls. | `lib.rs:554-591` |
| B7 | delivery | Automatic recovery never shrinks the range, so payloads averaging >~4 KiB can never catch up. | `wire.rs:634,686`; `lib.rs:3833` |
| B8 | delivery | The latest-value index never prunes; it fills and `stage_current` fails for good. | `current.rs:437-549` |
| B9 | store/runtime | The freshness anchor is not wired into restore. A rollback replays MLS state and reuses the SFrame counter (AES-GCM nonce reuse). | `persistence.rs:293-300`, `object.rs:275`; inferred from code, not probed |
| B10 | SDK | Go, Python and Swift hold the client lock inside `wait_for_work`; `close()` then deadlocks. Kotlin is correct. | `client.go:764`, `client.py:825`, `Client.swift:674` |
| B11 | SDK | The SDK's pinned core (7123166) is missing `fbc4e91` (wake host loop after delivery). | `git log 7123166..origin/main` lists `fbc4e91` |

## Architecture findings

### A1 — Contract: make one typed, versioned API (Critical)

- The FFI calls `arachne_runtime::execute` directly. `enum Request` (~93 ops, `deny_unknown_fields`)
  has no schema, no version op, and `String` errors. `Client` covers ~34 ops and is itself a JSON wrapper.
- `ErrorKind` is guessed from substrings (`client.rs:1741-1769`). The FFI drops even that: status 0/1/2 plus text.
- Each binding (Go, Python, Swift, Kotlin) retypes about 1,100 lines of DTOs and re-implements save → adopt.
- No `#[non_exhaustive]`; `Network::Tor` exists only under a feature flag; fixtures (`install_verified_policy`,
  `publish`/`poll`, `pub mod harness`) leak into the SDK surface.

**Change:** public, versioned request/response types (own module or crate), `api_version`/`capabilities` op,
typed error enums with stable numeric codes created where the error happens, `#[non_exhaustive]`
everywhere, and fixtures behind a `test-fixtures` feature. Strongly consider UniFFI (or a
protobuf schema) to generate the Kotlin, Swift, Python and Go bindings instead of hand-written ones.

### A2 — Commit ordering and removal (Critical)

- Any admin can commit management actions. Any member can commit Adds (`bootstrap.rs:304-311`, no admin check).
- Two commits at one epoch fork the group. The runtime detects it (`membership_branch_mismatch`) but
  does not resolve it. In a partition, the side that missed a Remove keeps sharing keys with the removed member.
- Ordinary members never self-update, so there is no post-compromise security for them.
- Invitation expiry is checked only by the committer (`bootstrap.rs:347`).
- The endpoint in the credential is self-claimed; other members cannot verify it.

**Decision needed:** pick one commit authority — a sequencer admin with failover, or a
deterministic tie-break (for example, lowest commit hash wins) with re-sync for the losing branch.
Then: admin-only Adds, a member self-update commit type, and endpoint-signed credentials.

### A3 — Epoch coupling breaks DDIL (Critical)

- Objects from a non-current epoch are rejected (`object.rs:299`). Every membership step clears the
  inbox, publisher log and receipts (`membership.rs:1932`).
- Pending objects block membership steps (`lib.rs:1385`), so a slow app or a flooding member can delay a removal.
- Routing requires an exact policy-revision match (`arachne-routing/src/lib.rs:123…357`), so one-behind peers lose all data.

**Change:** never let pending work block a membership step; keep a bounded window of past epoch
secrets for receive only; accept a small window of recent policy revisions; keep "who may recover"
(current roster) separate from "what was sent" (per-epoch logs).

### A4 — Process globals and lifecycle (High)

- `static REGISTRY`, a hard cap of 8 sessions (one workspace each), `DEVICE_OVERLAY_PATHS`, and one shared
  `ConnectionBudget`. Tests need `--test-threads=1`.
- One 2-worker Tokio runtime per client; the host cannot inject a runtime.
- `cancel` is sticky (only close resets). `wait_for_work` has no timeout. `close(&mut self)` cannot be
  called while another thread waits. One signal covers all queues, but the docs say to drain only admission.
- No suspend/resume or low-power hooks for Android; background timers keep running.

**Change:** an owned `Context` (limits, budget, shared runtime, registry) with a lazy default for FFI;
`wait_for_work(timeout)`, `wake()`, `close(&self)`; per-operation cancel or deadline; one
`next_event(timeout) -> Event` stream; `suspend()`/`resume()` plus a low-power profile.

### A5 — Persistence contract (High)

- `WorkspaceCandidate.snapshot` means the full state in host mode and a 37-byte token in native mode.
  Host mode cannot tell whether the host really saved the bytes.
- No `discard_candidate` on the Client; after a failed save the only way out is close and restore.
- `create_workspace` is not durable. The storage key comes from the endpoint secret, so a `Direct` client without a secret cannot persist.
- No schema version or migration in the store or runtime records; restore rejects unknown records.
  A crash between file create and the schema transaction bricks the store.

**Change:** make native storage the one supported mode behind a `Storage` trait and let core do
save → read back → adopt; separate the storage root from the endpoint key; add schema versions and migrations.

### A6 — Delivery semantics (High)

- Two receive stacks exist (legacy `ReceiveJournal` and the object `ObjectInbox`). Remove the legacy one.
- A global 528 KiB inbox cap with no per-author quota: one member can fill everyone's inbox.
- A 32-receipt window per (author, topic): late store-and-forward packets are dropped for good.
- Retention is tiny (32 packets or 512 KiB per topic) and shrinks silently when the inbox is full.
- Time is an unnamed `u64` with no skew rule. Payloads stop at 12–16 KiB with no blob-reference hook.
- Guarantees are not documented anywhere as one spec.

**Change:** write a delivery spec (group / direct / current), per-author quotas, bitmap dedup
separate from pending storage, byte-bounded recovery ranges, binary snapshots instead of JSON arrays.

### A7 — Network exposure and metadata (High)

- Non-members reach the data plane before any membership check and can hold the shared pools
  (32 exchanges, 4 blob slots) for ~5 s each (`budget.rs:177`).
- The gossip ALPN embeds an unkeyed hash of the workspace ID (`overlay.rs:480`); likely visible in the
  QUIC ClientHello (not yet confirmed with a pcap). ALPNs and mDNS say `data-fabric`.
- `Wan` uses n0's DNS and relays; the typed config cannot override this.
- The gossip path broadcasts to the whole swarm and only the receiver filters by policy;
  `Envelope.sender` is not authenticated at the node layer.
- The transport is not abstracted (Iroh types in the public API, 5 s / 2 s hard-coded timeouts), so radios
  and store-and-forward cannot plug in.

**Change:** gate the data plane on installed policy at the handshake; one fixed gossip ALPN with the
lookup inside the encrypted channel; operator relay and no-n0 as first-class config; a `Link` trait;
configurable timeouts.

### A8 — Topics are not isolated between apps (Medium)

One workspace key covers all topics; only AAD binds the topic. If many apps share a workspace,
each can read the others' data. **Change:** a per-app or per-topic exporter key, or one MLS group
per app or sensitivity level. At minimum, put an app ID in the AAD.

### A9 — Supply chain and packaging (Medium)

- Exact `=` pins on crypto and other crates in published libraries block patch uptake and unification.
- `[patch.crates-io]` fixes (bao-tree, netlink-packet-core, hax-lib-macros) do not reach downstream
  builds; the SDK copies the patch table by hand.
- Renamed forks reuse upstream version numbers.
- `license-file` instead of SPDX `license = "MPL-2.0"`; the SDK cdylib/AAR needs MPL notices.

**Change:** caret ranges plus a CI lockfile and cargo-deny; publish renamed forks with their own
versions (`-arachne.N`); an SPDX license field.

### A10 — Code structure (Medium)

`arachne-runtime/src/lib.rs` is 7,890 lines; `execute_in_session` is ~3,280 lines with 65 branches;
`Session` has ~60 fields. 24 of 26 integration tests drive raw JSON rather than the typed Client.
Split by subsystem (admission, join, recovery, publication, nearby, policy), each owning its state.

## Done well

- Stage → commit → adopt is enforced; network effects wait for the commit; the reset marker blocks resurrection.
- Bounded, versioned binary wire codecs; they reject trailing bytes and non-canonical data. No JSON on the wire.
- The delivery crate is a pure state machine; time is injected.
- Management commit checks are strict; joiners pin the checkpoint digest; the SFrame key comes from the MLS exporter.
- Recovery is author-signed and all-or-nothing; authorization is rechecked on every serve.
- `arachne-routing` is a clean zero-dependency crate. Blob grants are narrow and revocable.
- The FFI is careful: length checks, owned buffers, caught panics, a binary snapshot slot.

## Stale docs

`docs/integration.md` says protected receive and record storage are not typed (they are now) and
that crates are not published (README says they are). ADR 0008/0009 are cited but missing.

## Suggested order

1. Fix-now bugs B1–B11 (each is small).
2. Decide the commit-authority model (A2). Everything else in membership depends on it.
3. Define the versioned typed contract and error codes (A1) before Kotlin ships; consider UniFFI.
4. Context object, event stream, and lifecycle hooks (A4) — the Android plan needs these.
5. Epoch decoupling and the delivery spec (A3, A6).
