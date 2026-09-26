# Integrating Arachne Core

## BLUF

Use the typed `Client` in an owned `Context`, with storage configured before
workspace creation or join. Core owns save, read-back and adoption. The SDK
uses Core's types and UniFFI metadata to generate language bindings. The
application owns its payload rules and user interface, and protects endpoint
and storage-root secrets.

This development contract is API version 6. APIs, wire formats and saved state
can change before a stable release.
The typed entry point is `arachne_runtime::Client`. It is synchronous and belongs to a
`Context`, which owns or borrows its Tokio runtime. Call it from a blocking worker.
`Client::open` returns an `Arc<Client>` in the default shared context. Foreign bindings
use the same Core types through the optional `uniffi` feature; see the
[Core binding contract](reviews/h4-core-sdk-migration.md).

For a small runnable example, see
[`typed_pubsub.rs`](../crates/arachne-runtime/examples/typed_pubsub.rs). It
requires the `test-fixtures` feature and demonstrates two local clients, explicit
routing policy, topic interest, and opaque byte publication. It does **not** create an MLS workspace or demonstrate
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
| `RelayOnly` | Prefer relay-only transport behavior. | Set operator relays through `ClientConfig.transport.relay` when needed. |
| `WanOnly` | WAN lookup without LAN discovery or saved address hints. | Intended for diagnostics; direct paths remain enabled. |
| `Tor` | Tor hidden-service transport only. | Requires the `tor` feature, a stable endpoint secret, and a local Tor daemon; IP and Iroh relay transports are disabled. |

The typed `TransportOptions` record exposes operator relays, public lookup, transport
timeouts and an operation deadline. `Tor` stays in the enum when its feature is off;
selecting it then returns `Unsupported` (103).

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

## Context, events and deadlines

A `Context` owns a session table, connection budget, limits and one Tokio
runtime. `Client::open_in(context, config)` uses that context. `Client::open`
uses the lazy shared default. Rust hosts can supply a multi-thread Tokio
handle through `ContextConfig`; keep that runtime alive until its clients
close. Foreign callers can use `Context::owned(limits, power, workers)`.

Use Core's `default_limits`, `default_transport_options` and
`default_client_config` helpers instead of copying default numbers into an
adapter. `capabilities()` reports API version, supported networks and the
client context's limits. A stable `Network::Tor` variant is present even in a
build that reports it as unsupported.

Client methods are synchronous. Run them on a blocking worker, outside the
UI thread and outside an async runtime worker. A client is `Send + Sync`.
The wait methods hold no client or session lock while parked, so another
thread can wake or close the client.

| Operation | Host behavior |
| --- | --- |
| `next_event(timeout)` | Wait for a typed queue or job notification, then drain the matching work. `None` is no event. |
| `wait_for_work(timeout)` | Wait for any work, then poll or use `next_event`. `false` can mean timeout, wake or close. |
| `wake()` | Release one parked waiter without creating a work item. |
| `drive_workspace()` | Service native membership work and read `WorkspaceProgress`, including activity and branch outcomes. |
| `cancel()` | Interrupt the current blocking exchange. The cancellation does not remain set for the next operation. |
| `set_deadline(...)` | Set the deadline for later blocking operations. A deadline failure leaves the session usable. |
| `close()` | Close once, wake waiters and drain transport for at most `close_drain` (5 s by default). Repeated close is safe. |

Rust timeout and deadline values are `Option<Duration>`. `None` means no
specified timeout or deadline. `TransportOptions.deadline` also applies when
the endpoint binds. The separate transport timeouts bound dial, exchange,
gossip join and close drain.

Queue events repeat until their work is drained. Job-ready events occur once
per completed job. An event carries a scheduling signal; received content
stays in the durable inbox until the application adopts an acknowledgement
or rejection. A call made after close returns `Closed`; a wait already in
flight can return no work. Kotlin calls the native close operation
`shutdown`; generated `close()` releases its foreign handle.

`Context::suspend()` waits for each current operation, stops background
presence and gossip work, stops LAN discovery and closes idle connections.
It preserves workspace state, policy and queues; explicit operations still
work. `resume()` restarts background work and refreshes network paths. The
`Low` power profile multiplies background timer intervals by four. It does
not change the mDNS library's fixed announcement interval; suspend stops
that service.

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

For network joins, `drive_join` returns typed `JoinProgress`. Adopt a returned
`JoinCandidate`; a `Joined` result is already durable. `request_admission`
returns `AdmissionResponse`, and its opaque `AdmissionGrant` passes to
`stage_join_grant`. `poll_membership_update` returns an opaque `MemberUpdate`
that passes to `stage_membership_update`. These objects preserve the received
proof and bind it to the client that received it.

Publication and accepted live state wait for save, read-back and adoption.
An explicit staged membership offer sends a proposal; its receiver sends the
acknowledgement after durable adoption. If a save fails or does not read back,
the outcome is uncertain. Close the session and restore from storage before
further workspace operations; do not replay a cryptographic operation.

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
`MemoryProvider` is for tests. Foreign callers use
`StorageConfig::open_sqlite(directory, root)`, which validates a 32-byte root
and returns an opaque configuration object.

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

The typed restore result distinguishes `Active`, `Joining` and `Removed`.
A removed result ends the session. A roster can be present while branch
recovery blocks sending: inspect the activity and reason in
`WorkspaceProgress`, including `branch_orphaned` and `branch_send_quarantined`.

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

`install_policy` is a development fixture behind `test-fixtures`. It installs explicit
endpoint/topic permissions for a caller-supplied workspace and revision. `install_workspace_policy`
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
| Development fixture (`test-fixtures`) | `publish` and `poll` | Uses installed routing policy and Iroh transport. It does not encrypt the payload as an MLS group message. The example has no admitted workspace. |
| Protected workspace publication | `stage_protected_publication`, then `adopt_protected_publication` | Stages an MLS-protected publication and delays network effects until adoption. Adoption saves the candidate first. |

Production builds omit `install_policy`, `publish`, `poll` and the public harness.
With `test-fixtures` enabled, `publish` is rejected for a workspace after admission; the runtime directs the
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

`RecoveryRangeRequest { after: Some(cursor), through: None }` requests the
retained tail after a known authenticated sequence. This repair does not
advance full-history progress or claim the omitted history. The holder and
range proofs still need to pass validation.

## Resources and retained current values

The typed client exposes current-view fetch, poll, stage, adopt and cancel,
plus direct and range recovery from authorized peers. Current-value metadata
keeps its selector, replacement key, expiry and tombstone. A serving holder
can differ from the authenticated author.

`ResourceRequest` and `ResourceStatus` expose the existing Iroh Blobs service.
Membership, routing revision and a peer-bound read grant still apply. The
resource root is a blob cache; it does not confine host file access. The host
selects and validates source and destination paths and the content audience.
Catalog metadata alone does not prove that local blob bytes are present.

Automatic current-value re-publication across every normal epoch change is
still a separate gap. Losing-branch re-publication has the bounded behavior
in [Security](security.md#retained-data-and-local-actions).

## Errors and binding contract

Use `ApiError` and its stable numeric code. Do not match error text. Core
validates supplied secret bytes; malformed custom ID values can fail binding
conversion before a Core operation. Preserve the generated Core ID types,
candidate objects and error values in each language adapter.

Enable `arachne-runtime/uniffi` to export Core metadata. Production SDK builds
leave `test-fixtures` and `debug-rig` disabled. The
[Core binding contract](reviews/h4-core-sdk-migration.md) records namespaces,
Swift packaging, defaults and the typed operation groups.

## Remaining integration gates

- The Core JSON dispatcher remains for existing native adapters and
  qualification callers. New integrations use the typed Client. Removing
  the dispatcher depends on migrating those callers.
- Existing app databases need an authenticated, crash-safe one-time upgrade
  before a new Core pin is deployed. Moving the database path alone does
  not upgrade its encrypted records or inbox format. See the
  [device upgrade gate](reviews/h4-core-sdk-migration.md#device-upgrade-gate).
- The owner must select the SDK line and approve the ATAK host/classloader
  qualification and release actions. Host/AAR build evidence does not
  establish a working ATAK installation.

The [work tracker](reviews/2026-09-24-work-tracker.md) records completed work,
proof receipts and the remaining decisions.
