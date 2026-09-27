# Arachne threat model

Version: 1.0

Status: pre-release baseline

Last reviewed: 2026-09-26

Scope: Arachne Core, generated UniFFI SDK, Arachne ATAK plugin, and Arachne PTT app

This document defines the security claims Arachne intends to make, the trust
boundaries those claims cross, and the evidence required before release. It is
an engineering threat model, not an independent audit or certification.

Core maintainers own protocol and Rust controls. SDK maintainers own the
generated foreign-language boundary. Android application and plugin maintainers
own platform storage, IPC, permissions, logging, signing, and update controls.
Deployers own relay, Tor, device, account-enrollment, backup, and incident
response policy.

Review this document when a wire or storage format changes, a cryptographic or
transport dependency changes, a new host boundary is added, or a new deployment
profile becomes supported.

## Security objectives

Arachne protects these assets:

1. workspace membership authority and administrator intent;
2. MLS epoch secrets, endpoint secrets, storage roots, invitation secrets, and
   derived object keys;
3. confidentiality, integrity, authorship, audience, and replay state for
   protected publications;
4. durable membership, counters, candidates, recovery records, and rollback
   anchors;
5. endpoint and workspace availability within explicit resource bounds;
6. host-visible plaintext, roster information, audio, location, and other
   application data;
7. release artifacts, dependency provenance, and signing identities.

Availability across a hostile or disconnected network is a goal, not a
guarantee. An endpoint identifier is a cryptographic network identity, not a
verified person, organization, or device owner. Topics and application
namespaces are routing and domain-separation mechanisms; they do not provide
confidentiality between members of the same MLS workspace.

## Security invariants

These rules are release-blocking invariants.

| ID | Invariant | Primary owner |
| --- | --- | --- |
| INV-1 | Only a verified MLS history and Arachne authorization proof may change workspace membership or roles. Network reachability, endpoint authentication, relays, gossip tags, and display names grant no workspace authority. | Core security |
| INV-2 | A live cryptographic state or network-visible operation does not advance until its exact candidate is saved, read back, and adopted. | Core runtime and store |
| INV-3 | Competing membership histories are ordered by the documented verified rule. A required removal or leave quarantines new protected sends until the winning state is durable. | Core security and runtime |
| INV-4 | Protected sends use the current accepted epoch. Retained past-epoch keys are receive-only and bounded. A removed member cannot authorize new traffic. | Core security and delivery |
| INV-5 | The workspace, application namespace, topic, author, object identifier, sequence, audience, and epoch are cryptographically bound wherever the protocol says they are authoritative. | Core security and delivery |
| INV-6 | Every network, wire, storage, and FFI input is bounded before allocation or state mutation. Failure is explicit and does not silently broaden authority. | Core, SDK, Android hosts |
| INV-7 | A relay, lookup service, local network, Tor peer, gossip peer, or blob source cannot substitute data or membership without a later cryptographic verification failure. | Core node and security |
| INV-8 | Restored state is authenticated. Whole-database rollback is detected only when an independent freshness anchor is configured; the absence of that anchor remains visible as deployment risk. | Core store and host |
| INV-9 | Foreign callers cannot reuse a stale or cross-client candidate or handle, race close/use into undefined behavior, or receive secrets through error text, formatting, logs, or generated debug output. | SDK and host |
| INV-10 | Android IPC and exported components authenticate the actual sender where the platform permits it and require explicit user approval where it does not. IPC data never grants Core membership by itself. | ATAK plugin and PTT app |

## Adversaries and assumed capabilities

The model includes:

- a remote unauthenticated peer that can connect, disconnect, retry, fragment,
  reorder, duplicate, delay, or send malformed and oversized input;
- a hostile relay, discovery service, ISP, Wi-Fi network, or Tor path that can
  observe metadata, deny service, replay packets, and return stale or false
  routing information;
- a malicious or compromised current workspace member that holds legitimate
  group secrets and can publish, withhold updates, fork concurrently, leak
  plaintext, or collude with other members;
- a malicious administrator that can exercise every authority the current
  policy legitimately gives an administrator;
- an attacker with filesystem access who can copy, replace, truncate, or roll
  back the database and backups but does not initially know the storage root;
- malformed, concurrent, stale, or adversarial calls through generated UniFFI
  bindings and Android lifecycle boundaries;
- an app on the same Android device attempting to spoof or replay ATAK/PTT IPC;
- a compromised dependency, build input, or release artifact.

The model does not claim to preserve secrets after full compromise of a
running authorized process, unlocked device, current member, administrator, or
release signing identity. It seeks to limit persistence, detect invalid state,
and provide recovery and revocation procedures after compromise.

## Trust boundaries

| ID | Boundary and data crossing it | Current controls | Evidence and executable checks | Residual risk and required owner action |
| --- | --- | --- | --- | --- |
| TB-1 | Application host to typed Core client: names, policies, publications, deadlines, storage roots, endpoint secrets | Typed API, stable error codes, candidate ownership, context limits, size validation, stage/save/read/adopt | Core: runtime `candidate_handles.rs`, `context.rs`, `record_bounds.rs`, `storage_root.rs`, `typed_publication_options.rs` | A malicious host already sees plaintext and supplied secrets. Host owner must protect inputs, logs, and lifecycle. |
| TB-2 | Internet or LAN to Iroh endpoint: QUIC packets, endpoint IDs, addresses, ALPN, timing | Iroh endpoint authentication, TLS/QUIC integrity, fixed protocol names, connection budgets, deadlines, members-only data handshake | Core: node `control_burst.rs`, `connection_memory.rs`, `connection_reuse.rs`, `live_pubsub.rs`, `wan_profile.rs` | Traffic analysis, blocking, stale routes, implementation defects, and resource pressure remain. Core node owner maintains adversarial network tests. |
| TB-3 | Relay, address lookup, mDNS, or Tor service to endpoint | Route data is connectivity input only; workspace operations still require endpoint, policy, MLS, signature, and object verification. Operator relays and public lookup are configurable. Tor has no direct-IP or Iroh-relay fallback. | Core: runtime `transport_options.rs`, `tor_client.rs`, `nearby_invitation.rs`; node `tor_transport.rs`, `wan_profile.rs`, `mdns_refresh.rs` | Operators learn path-specific metadata and can deny service. Tor remains experimental and requires deployment qualification. Operator owns service trust and logs. |
| TB-4 | Authenticated endpoint connection to workspace authorization | Installed policy gates data peers; control and gossip inputs are parsed within bounds; gossip tag is not treated as authority | Core: node budget and `membership_gossip_size.rs`; runtime `gossip_key.rs`, `topic_rules.rs` | A current member can retain the stable gossip key after removal and calculate the tag. Policy and MLS checks remain mandatory. |
| TB-5 | Member or administrator to MLS group state: proposals, commits, welcomes, credentials, revocation proofs | Endpoint-signed credentials, admin-only privileged actions, deterministic branch order, bounded proof history, send quarantine, self-update and leave rules | Core: `arachne-security` suite, security `invitation_controls.rs`, `leave.rs`, runtime membership fork and convergence tests | A legitimate administrator can abuse granted authority. A partition delays knowledge of removal. Independent MLS integration review remains open under `ptt-60z.3`. |
| TB-6 | Out-of-band invitation to join protocol | Invitation/checkpoint binding, expiry and use controls, request approval, authenticated admission, checkpoint and history verification | Core: security and runtime `invitation_controls.rs`, runtime `invitation_checkpoint.rs`, `offline_invitation.rs`, `admission_staging.rs` | Anyone who obtains a reusable invitation can request admission under its policy. The channel carrying the link controls its exposure. App and operator own link handling. |
| TB-7 | Gossip, control, direct recovery, and retained data to local accepted state | Signed/authenticated messages, exact workspace/epoch/topic binding, byte and count bounds, all-or-nothing recovery, current-roster authorization | Core: runtime `recovery_epoch_window.rs`, `recovery_quota.rs`, `third_holder_recovery.rs`; node gossip forwarding and mixed-traffic tests | Peers can withhold data or exhaust permitted quotas. At-least-once delivery permits duplicates. Application owner must tolerate documented delivery semantics. |
| TB-8 | Core to SQLite/filesystem/backup and optional freshness anchor | AES-256-GCM records, authenticated index, separate storage root, atomic candidate transaction, format rejection, optional independent anchor | Core: store tests; runtime `native_persistence.rs`, `freshness.rs`, `storage_format.rs`, `record_storage.rs` | Without an anchor, whole-database rollback can roll back MLS state and counters together. Host owns root-key, anchor, backup, file-permission, and single-open enforcement. |
| TB-9 | Rust Core to generated UniFFI libraries and Kotlin, Swift, Python, or Go callers | Core-owned UniFFI metadata, generated bindings, typed errors, opaque handles, bounded byte conversion, panic containment | SDK: `crates/arachne-sdk/tests/`, `tests/uniffi/*`, Android smoke `ClientAndroidTest.kt` | Language runtimes add cancellation, callback, GC, class-loader, and packaging behavior. `ptt-60z.6` owns malicious-boundary and device qualification. |
| TB-10 | SDK and Android platform to ATAK plugin | App-private storage, Android Keystore wrapping, package/signature checks, explicit manifests, sender validation and user approval for linking | ATAK: `scripts/check-host.sh`, `FabricSessionInstrumentation.kt`, `PeerAdmissionCheck.kt`, `StorageCrashCheck.kt`, manifest review | Android 13 and older cannot provide the same sender identity signal used on Android 14+. A leaked proof `PendingIntent` can be replayed; user approval remains the compensating control. ATAK owner tracks this residual risk. |
| TB-11 | ATAK plugin to PTT app IPC and PTT media/storage | Narrow intents, link state, workspace-scoped routing, application permissions, explicit talk/floor controls | PTT: backend `AtakLinkTest.kt`, `PluginWorkspaceIntentTest.kt`, `TalkRouterTest.kt`, `PttAudioBackpressureTest.kt`; manifest review | IPC spoofing, accidental cross-workspace routing, audio capture, notification, backup, and crash-log leakage require Android device tests. PTT owner maintains these gates. |
| TB-12 | Source and dependencies to release artifacts | Locked dependencies, maintained fork names and patch notes, advisory checks, generated-code comparison, release signing | Core `cargo deny`, SDK binding smoke, dependency evidence under `docs/evidence/` | The project has not established complete SBOM, provenance, emergency update, or vendor-exit gates. `ptt-60z.5` and `.7` own them. |

## Threat register

| Threat | Preventive or detective controls | Remaining exposure and response |
| --- | --- | --- |
| Unauthorized admission or role change | Verified MLS commits, endpoint-bound credentials, invitation controls, administrator authorization, exact proof-path verification | Compromised administrators retain legitimate authority until demoted or removed. Audit roster changes and provide an operator recovery procedure. |
| Concurrent commits and malicious fork choice | Total deterministic ordering over verified actions, removal priority, snapshot replay, public pins, send quarantine | A node older than retained recovery state becomes orphaned and needs explicit re-admission. Network partitions can delay convergence. |
| Removed member reads or sends data | Current-epoch sends, roster and signature validation, removal key rotation, receive-only bounded old epochs | Previously received plaintext cannot be recalled. A removed member keeps old plaintext, old epoch secrets within its captured state, and the stable gossip tag key. |
| Replay, duplicate, or reordered protocol input | Signed context, counters, epochs, candidate single-use, dedup windows, canonical codecs, recovery digests | At-least-once delivery intentionally permits application-visible duplicates. Hosts must make effects idempotent where required. |
| Database rollback or cloning | Authenticated records and index; optional external freshness anchor; endpoint and storage keys are distinct | Authentication alone does not detect whole-database rollback. Production hosts that need rollback detection must provide and test an independent anchor. Concurrent clones of one endpoint identity are unsupported. |
| Storage-root or endpoint-key compromise | Platform protection, separate derivation domains, membership removal and self-update, bounded retained secrets | Core cannot recover confidentiality after key disclosure. Rotate the endpoint, remove/re-admit membership as needed, replace the storage root through an authenticated migration, and assume captured old plaintext remains exposed. |
| Host, log, crash report, or backup leaks plaintext or keys | Redacted formatting, app-private storage, explicit host duties, generated-boundary tests | A compromised authorized host is inside the confidentiality boundary. Android owners must inspect backup policy, logs, tombstones, screenshots, clipboard, and crash collection. |
| Hostile relay, lookup, LAN, ISP, or Tor path | End-to-end endpoint and MLS checks; operator service configuration; Tor-only profile isolation | Path operators can observe endpoint IDs, addresses, timing, volume, and relationships and can block service. No anonymity claim is made. |
| Resource exhaustion by peers or members | Frame limits, byte/count quotas, connection and session budgets, timeouts, bounded queues, stranger reservations | Bounds can still be consumed to deny useful work. `ptt-60z.4` must measure CPU, memory, disk, recovery, and fairness under sustained faults. |
| Malformed FFI or lifecycle calls | Generated types, size validation, opaque handles, caught panics, close/wake tests | Cancellation, callback re-entry, stale handles, process death, and language-specific ownership need the expanded `ptt-60z.6` matrix. |
| Dependency or build compromise | Lockfile, advisory policy, fork provenance notes, generated output checks | No independent audit, complete provenance chain, or emergency patch SLA exists yet. Release remains pre-audit until `ptt-60z.3`, `.5`, and `.7` close. |

## Key and recovery responsibilities

| Secret or authority | Created and used by | Required protection and recovery rule |
| --- | --- | --- |
| Iroh endpoint secret | Host/Core endpoint | Persist securely for stable identity. Do not run concurrent clones. Compromise requires a new endpoint and workspace-level removal/re-admission. |
| MLS credential and epoch state | Core security | Never exported as host-managed plaintext state. Persist only through the authenticated candidate path. Recover from a verified snapshot or re-admit; never invent missing history. |
| Storage root | Host | Store separately from the database, normally under platform key protection. Loss makes the database unrecoverable; disclosure exposes records copied with it. |
| Freshness anchor | Core through host `AnchorStore` | Store outside the rollback domain of the SQLite database. If deployment requires rollback detection, absence or mismatch must block restore. |
| Invitation bearer material | Core, then application/user channel | Treat as a capability. Limit reuse and lifetime, redact from logs, and revoke or disable after suspected disclosure. |
| Gossip key | Core MLS welcome/state | Treat as overlay metadata protection, not authorization. Removal does not rotate it in the current protocol. |
| Android Keystore wrapping and signing keys | Android host/release owner | Exclude or migrate backups deliberately, bind aliases and ciphertext to the right installation, protect release signing, and test process death and app upgrade. |

## Assurance plan and evidence ceiling

The threat model defines the following work program:

- `ptt-60z.2`: fuzz untrusted decoders and state transitions;
- `ptt-60z.3`: independently review MLS, Iroh, gossip, and Tor composition;
- `ptt-60z.4`: exercise adversarial networks and resource exhaustion;
- `ptt-60z.5`: govern dependencies and retire vendor patches;
- `ptt-60z.6`: review generated SDK, Android IPC, and key storage;
- `ptt-60z.7`: establish disclosure, compromise response, and release gates.

Rust unit and local integration tests establish only the behavior they execute.
They do not prove the MLS protocol, Iroh, Tor, Android, a production relay,
wide-area reachability, resistance to a compromised authorized endpoint, or
security certification. Production claims require the applicable child work,
device and deployment evidence, and an independent review.

Before a security release, reviewers must:

1. map every material change to an invariant and trust boundary above;
2. run the focused checks named for affected boundaries;
3. record dependency, fuzz, adversarial-network, SDK/mobile, and migration
   evidence required by the open assurance beads;
4. block unresolved high-severity findings or document an owner-approved,
   time-bounded exception with compensating controls;
5. update this version when assumptions, controls, or residual risks change.
