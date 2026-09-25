# Integrating Arachne Core

This repository is a pre-release Rust workspace, not a stable SDK. All eight
crates have an initial release on crates.io. APIs, wire formats, and saved
state can change.
The current typed entry point is `arachne_runtime::Client`. It is synchronous
and owns a Tokio runtime internally, so call it from a blocking worker rather
than from inside an application's async executor or UI thread.

For a small runnable example, see
[`typed_pubsub.rs`](../crates/arachne-runtime/examples/typed_pubsub.rs). It
demonstrates two local clients, explicit routing policy, topic interest, and
opaque byte publication. It does **not** create an MLS workspace or demonstrate
protected group messaging.

## Client startup and identity

`Client::open` takes a `ClientConfig` with a `Network` profile and optional
32-byte endpoint secret. The secret is an endpoint credential; it is not an
MLS workspace key or a human identity. Supply a securely persisted secret when
the host needs a stable endpoint identity across restarts. Protect it as a
secret. The `Direct` profile permits an omitted secret for ephemeral use; the
other typed profiles require one.

| `Network` | Current intent | Important limit |
| --- | --- | --- |
| `Direct` | Direct endpoint connection with no discovery preset. | The host may need to provide address hints. |
| `Lan` | LAN discovery and direct paths. | Does not imply internet-wide lookup. |
| `Nearby` | Nearby/local discovery behavior. | Deployment and platform discovery conditions apply. |
| `Wan` | Public lookup and relay-assisted connectivity. | Does not guarantee a usable route. |
| `RelayOnly` | Prefer relay-only transport behavior. | A custom operator relay is not configurable through `ClientConfig` today. |
| `WanOnly` | WAN lookup without LAN discovery or saved address hints. | Intended for diagnostics; direct paths remain enabled. |
| `Tor` | Tor hidden-service transport only. | Requires the `tor` feature, a stable endpoint secret, and a local Tor daemon; IP and Iroh relay transports are disabled. |

The lower-level node/runtime surface has additional relay configuration. The
typed `ClientConfig` does not currently expose it as an adopter-ready option.

`Tor` is experimental because it uses Iroh's unstable custom-transport API.
The Tor transport creates an ephemeral onion service from the endpoint identity,
so peers can dial by endpoint key without an IP address hint. It expects the
Tor SOCKS5 and control ports at `127.0.0.1:9050` and `127.0.0.1:9051`. Keep the
endpoint secret stable to keep the same endpoint identity and derived onion
address across restarts. The profile does not fall back to direct IP or Iroh
relay paths.

The Docker-backed Core integration check is ignored in ordinary test runs and
can be run with a local Tor daemon available on those ports:

```sh
cargo test -p arachne-node --features tor --test tor_transport -- --ignored --nocapture
cargo test -p arachne-runtime --features tor --test tor_client -- --ignored --nocapture
```

## Workspace lifecycle

The typed API exposes workspace creation, join/admission staging, adoption,
invitations, rosters, and management operations. A typical join path has these
conceptual steps:

1. The joining client calls `begin_join` with invitation material and a display
   name.
2. The workspace owner validates the request with `stage_admission`.
3. The owner calls `adopt_admission` with the returned candidate. Core saves
   it to record storage, reads it back, then adopts it. The owner can then
   obtain the retained welcome/commit reply.
4. The joining client calls `stage_join`, then `adopt_join`.
5. Both adapters refresh routing policy from the accepted workspace state.

The stage/adopt boundary is intentional. Core does not emit network effects or
advance live state before the candidate is saved and read back. If a save fails
or does not read back, the outcome is uncertain: the session then refuses every
op except `reset_workspace`, `workspace_state` and close. Close it and restore
from storage; do not replay a cryptographic operation.

### Persistence contract

Native record storage is the only persistence mode. The host attaches a
`StorageConfig` to the session (`ClientConfig::storage`, or `attach_storage`
for the JSON dispatcher) before it creates, joins or restores a workspace.
`StorageConfig::sqlite(directory, root)` keeps one encrypted SQLite file per
workspace in a private directory. `root` is the host's storage root key. It is
separate from the endpoint secret: a `Direct` client without an endpoint secret
can persist, and a new endpoint identity does not change how the store is read.
Workspace state itself is bound to the endpoint key (MLS membership), so a
store written by one endpoint restores only under that endpoint; another
endpoint gets `WrongState`, and the store stays intact.
`StorageConfig::new` takes any `StorageProvider` implementation;
`MemoryProvider` is for tests.

A stage op returns an opaque candidate, never state bytes. In the typed
`Client` each kind has its own type (`WorkspaceCandidate`, `InvitationCandidate`,
`RemovalCandidate`, `JoinCandidate`, `PublicationCandidate`,
`ProtectedReceptionCandidate`, `RecoveryCandidate`), so a candidate only compiles
with its own adopt method. A candidate is bound to the client that staged it
(another client gives `WrongState`) and works one time (a second adoption gives
`CandidateStale`). `discard()` drops it; a candidate dropped without adoption is
discarded too. A candidate that is already in storage cannot be discarded. The
JSON dispatcher returns the token in `candidate`, and each adopt op refuses a
candidate of another kind (`WrongState`); `discard_candidate {candidate}` drops
exactly that one. The matching
adopt op saves the candidate, reads it back, then adopts it. `create_workspace`
and `begin_join` save their state before they return, so every reply reports
`durable: true`. `restore_workspace(workspace)` restores what storage holds for
that workspace: an active workspace, a pending join, or this member's removal
(the session then ends). The host never saves or passes state bytes, and there
is no import of old state: an import would be a rollback.

The host still protects the root key and the storage directory. See
[Security](security.md#local-persistence).

Rollback detection needs a freshness anchor kept outside the database. If
the platform has monotonic storage, give it to core with
`StorageConfig::with_anchors(anchor_store)`: core saves the anchor with every
commit and restore requires it (see [Security](security.md#local-persistence)).
Otherwise the host keeps the anchor:

- Call `record_freshness` (or `Client::record_freshness`) after every call that
  can commit, and persist the anchor before you release that call's result.
  For FFI, `FreshnessAnchor::to_bytes` gives 40 bytes: the big-endian revision,
  then the digest. `FreshnessAnchor::from_bytes` reads them back.
- Restore with the anchor (`restore_workspace` with `freshness`, or
  `Client::restore_workspace(workspace, Some(anchor))`). The store must match
  the anchor exactly. An older store and a newer store are both rejected
  before any record is read, and the session stays empty.
- Without an anchor, restore does not detect a rollback.

## Routing and permissions

`install_policy` installs explicit endpoint/topic permissions associated with a
workspace and caller-supplied policy revision. `install_workspace_policy`
derives an all-current-members, all-topics policy from the current MLS roster;
it is a convenience policy, not a least-privilege policy. An adapter should
only install policy derived from accepted, current workspace state.

`set_interest` separately asks to receive a topic. Interest does not grant
permission, and permission does not automatically mean the application wants
to display or persist that topic. Topics are routing labels, not separate MLS
groups; use a separate cryptographic workspace where distinct confidentiality
boundaries are required.

## Publication paths

There are two paths that must not be conflated:

| Path | API | Security meaning |
| --- | --- | --- |
| Basic transport/pub-sub example | `publish` and `poll` | Uses installed routing policy and Iroh transport. It does not encrypt the payload as an MLS group message. The example has no admitted workspace. |
| Protected workspace publication | `stage_protected_publication`, then `adopt_protected_publication` | Stages an MLS-protected publication and delays network effects until adoption. Adoption saves the candidate first. |

`publish` is rejected for a workspace after admission; the runtime directs the
caller to the protected path. Do not use the basic example as a secure group
messaging recipe. The typed facade receives with `poll_protected` and
`adopt_protected_reception`, then reads the inbox with `poll_pending_object`
and resolves each object with `stage_object_acknowledgement` or
`stage_object_rejection` (then `adopt_protected_reception`).

## Recovery and delivery expectations

Received and recovered objects wait in a durable inbox. Read them with
`poll_pending_object`, then stage and adopt an acknowledgement or rejection.
Recovery is peer-assisted and bounded; it is not a central durable queue. A
successful send/admission report does not mean every offline peer has
received the data. [Delivery semantics](delivery.md) states the guarantees
of each mode: at-least-once delivery, duplicates, ordering, loss, recovery,
retention bounds and epoch behavior.

## Known integration gaps

Before presenting this as a supported application SDK, close or explicitly
accept these gaps:

- `ClientConfig` does not expose custom relay settings available in lower-level
  transport construction.
- Synchronous methods need a documented host threading and cancellation model
  for each target runtime, especially Android.
- The public API has not been declared stable. The crates have an initial
  crates.io release, but APIs, wire formats and saved data can still change.

The typed `Client` covers the record-storage lifecycle (`ClientConfig::storage`,
`restore_workspace`, `record_freshness`) and protected receive with durable
adoption (`poll_protected`, `adopt_protected_reception`).

These are concrete implementation boundaries, not guarantees about the timing
of future releases. Check the current API and tests before integrating.
