# Architecture

The data fabric is an embeddable peer-to-peer collaboration library. Each participating device or service runs a local fabric endpoint. Applications use it to join workspaces and publish or subscribe to data without connecting to a mandatory central TAK Server.

The first application is a Kotlin ATAK plugin backed by a portable Rust implementation. Non-ATAK applications and streaming publishers/subscribers use the same core. ADS-B and AIS are illustrative sources, not prescribed schemas or first-test formats. The architecture describes the target system; the implementation inventory below identifies what exists today.

## System shape

An application adapter translates its own concepts into fabric operations. The local fabric validates workspace authority, protects publications, routes them to interested authorized recipients and manages delivery/recovery. Peer connectivity supplies authenticated paths between endpoints.

A device can belong to several workspaces. The workspaces share networking resources where useful while keeping authority, keys, subscriptions and stored data isolated. A socket is not a workspace, and a workspace does not require a connection to every member.

Resource sharing must not introduce a public identifier linking memberships.
Each workspace has separate transport and membership credentials. With the
current Iroh backend, this requires separate authenticated endpoint identities,
not merely different workspace IDs carried over one identifiable endpoint.
The runtime may share local scheduling and storage infrastructure while keeping
those credentials separate. Multi-workspace endpoint orchestration is not yet
implemented; the current plugin operates one explicit development fixture.

The system has three logical traffic classes:

- **Membership control:** credentials, authorized management actions, cryptographic transitions and their recovery dependencies.
- **Live data:** current publications and subscription interest, bounded by freshness and queue limits.
- **Catch-up:** retrieval of retained application data and required recovery state from available holders.

These are responsibilities within endpoints, not three required server deployments. Control traffic needs enough reserved capacity to avoid being starved by high-rate feeds or large content.

## Components and seams

| Component | Owns | Boundary contract |
| --- | --- | --- |
| Application adapter | Application objects, UI, contact/recipient intent and rendering | Calls workspace and pub/sub operations with explicit scope; receives typed application bytes and status |
| Portable fabric facade | Composition and application-facing lifecycle | Asynchronous operations, bounded events, cancellation and shutdown; no ATAK or vendor-library types |
| Group security | Verified membership, policy authority, credentials and protected group transitions | Accepts management intent; verifies state changes and publications; exposes accepted authority to routing |
| Routing and delivery | Interest, recipient selection, backpressure, deduplication, expiry and repair | Receives verified scope/authority; produces bounded send and storage work |
| Peer connectivity | Endpoint authentication, discovery hints, dialing, path changes and reconnect | Delivers framed bytes over authenticated peer paths; does not grant workspace authority |
| Persistence | Durable identities, security state, pending operations and retained records | Atomic recovery boundaries and bounded retention; no dependency on ATAK lifecycle |

These seams isolate the parts expected to change with field experience. They do not require a runtime plugin framework. Start with one implementation per responsibility and ordinary Rust modules or crates. A module should be separately reusable when its contract is useful independently; splitting every type into a crate provides no benefit.

Applications should not receive Iroh endpoints, MLS objects, database handles or Android objects through the fabric API. Transport substitutions should affect connectivity code. A crypto substitution can require a coordinated protocol migration or rejoin even when the local interface remains stable.

## Deployment and trust roles

| Role | Can contribute | Must not obtain merely by holding the role |
| --- | --- | --- |
| Member endpoint | Publish/read authorized data, exchange control state, optionally retain data | Administration or access to unrelated workspaces |
| Administrator endpoint | Issue authorized management actions | Permanent ownership of availability or an ability to bypass peer validation |
| Discovery helper | Return candidate contact information | Identity or membership authority |
| Transport relay | Carry encrypted traffic when direct paths fail | Application plaintext or authority to admit a participant |
| Retention helper | Hold bounded encrypted records for later retrieval | Decryption keys or management rights by default |

Roles may coexist on one device, but they remain distinct permissions. A stable feed service could improve availability without becoming a workspace administrator. Helper deployment and ownership are open choices; no single helper may become an undisclosed mandatory dependency.

Serverless means that collaboration does not require users to provision a central collaboration authority. It does not mean that every pair of phones can establish a direct connection through every network, or that offline data needs no storage.

## Main flows

### Create and join

A creator establishes a workspace identity, initial policy and secure local state. An invitation carries authenticated workspace information, a scoped admission capability and replaceable discovery hints. A joiner authenticates the intended workspace and its reachable peers, obtains any required approval, reconciles the accepted membership transition and acquires usable cryptographic state.

The UI reports readiness only after admission and required key synchronization succeed. A second administrator can manage according to policy without depending on the creator's presence. [Security and groups](security-and-groups.md) defines the required authority and partition behavior.

### Publish and receive

1. The adapter supplies workspace, topic, payload and recipient/freshness intent.
2. The fabric checks local authority and assigns the publication identity needed for retries and receipts.
3. Group security protects content for its intended readers and binds the required author/context information.
4. Delivery selects authorized interested recipients or overlay neighbors and applies queue/retention policy.
5. Connectivity transmits over available authenticated paths, directly or through permitted relays.
6. Receiving endpoints verify the publication and accepted authority, reject duplicates/expired data as appropriate, and deliver only within the matching workspace subscription.
7. The receiving adapter maps the publication into native application behavior without echoing it back as a new outbound publication.

The final protocol must authenticate the original author independently of the immediate transport peer. Hop-level transport encryption is sufficient only for the current direct-link experiment, not for the target forwarded/group fabric.

### Reconnect and recover

An endpoint loads durable identity and security state, discovers a usable path and reconciles missing control dependencies. It repairs subscriptions and obtains permitted retained data within the supported retention window. Recovery may produce explicit rejoin-required or data-unavailable results. It must not conceal an unsafe rollback behind a connected indicator.

### Revoke

An authorized management action changes accepted authority and cryptographic access. Routing removes no-longer-authorized interests and rejects subsequent unauthorized operations under the accepted state. Peers that have not learned the change may still act under their older state; partition policy must state that boundary honestly. Previously learned plaintext cannot be recalled.

## ATAK integration

The plugin owns workspace creation/join UI, invitations, member management, visible connection state and outbound sharing scope. Native ATAK features remain the user-facing data experience: PLI, GeoChat and shared points are first targets, followed by a measured compatibility inventory.

Transport should be unobtrusive within supported native workflows: a user selects
an ATAK contact, chats, or shares an object through ATAK's normal controls. The
plugin supplies workspace and membership management rather than a replacement
chat or map. Transparency must not hide audience ambiguity: outbound workspace
scope, unresolved recipients, and pending or failed delivery must be visible.
Native contact appearance alone does not establish working private messaging.
Directed delivery requires an authenticated workspace-specific mapping from ATAK
recipient identifiers to authorized fabric recipients and protection that excludes
other members. Unsupported directed operations must never fall back to broadcast.

The adapter must preserve recipient privacy and distinguish native application identifiers across workspaces. It must suppress loops when fabric-delivered data enters ATAK. Existing native network paths must be controlled so a disconnected-fabric negative test cannot pass through ATAK's default LAN traffic.

The normal workspace adapter translates supported native PLI, direct/group chat
and map items into protected publications and imports scoped events through ATAK's
CoT dispatcher. Accepted members appear as ordinary ATAK contacts. Users create
groups and open conversations with ATAK's existing Contacts and Messages tools;
Arachne adds no conversation or inbox. Incoming author identifiers come from
verified fabric metadata, and addressed chat is resolved against the accepted
workspace roster without widening an unresolved audience to broadcast.

The debug CoT fixture and local stream experiment are separate diagnostic paths;
loopback alone does not authenticate clients.
The binding and adapter must not block ATAK's UI thread, and stopping the plugin
must release native resources.

The supplied SDK is the compatibility baseline. Plugin packaging, signing and native-library loading must be verified in the actual ATAK host, not inferred from a standalone Android executable. Detailed current evidence is in [STATUS.md](../STATUS.md).

## Non-ATAK integration

A feed process joins a workspace as an authorized service participant, subscribes or publishes through the portable interface and uses an application payload format appropriate to its data. It does not impersonate an ATAK contact or wrap everything in CoT.

Adapters own source observation timestamps, entity identifiers and conversion/rendering. The fabric owns publication identity, authority, delivery and workspace isolation. Feed permissions can be narrower than human collaboration permissions; read confidentiality must also match the cryptographic audience.

### Feed discovery and selection

An authorized publisher advertises a feed within its workspace. The plugin lists
its human-readable name, publisher, supported format and freshness, and offers
Subscribe/Unsubscribe. Discovery is available by default to authorized members;
optional external streams require selection rather than starting every feed on
workspace entry. Existing ATAK collaboration defaults remain separate.

The initial candidate uses bounded metadata over an ordinary protected discovery
topic, with periodic refresh and expiry. The descriptor identifies the feed,
workspace-scoped publisher, revision, format and exact data topics. An advertisement
cannot grant permissions, claim another publisher's identity or change membership.
Late joiners must receive a refresh without requiring an administrator online.
Expired advertisements indicate stale availability, not revoked membership.
Subscriber preferences survive temporary publisher absence; resumption obeys
current authorization and data freshness rules.

The portable fabric treats feed payloads as bytes. A source adapter ingests ADS-B;
the ATAK adapter converts supported observations into tracks. Unsubscribing stops
future routing; existing displayed tracks follow explicit stale/expiry behavior.
This mechanism is a candidate awaiting implementation and integrated validation.

## Current implementation inventory

| Location | Implemented responsibility | Boundary still missing |
| --- | --- | --- |
| `android/` | Kotlin workspace creation/join/reopen, saved-state coordination, native ATAK contacts, direct/group chat, PLI and map sharing | Complete native compatibility and broader field acceptance |
| `crates/arachne-routing/` | Exact-topic endpoint permissions and subscription routing | Distributed mutable policy negotiation and finer selectors |
| `crates/fabric-android/` | JNI conversion, exception handling and Android diagnostics over the shared runtime | Broader device/ABI validation |
| `crates/arachne-runtime/` | Portable session composition, verified admission, roster-derived policy, signed-object inbox/ack and recovery with staged snapshot adoption | Complete membership history distribution, service feed workflow and measured capacity |
| `crates/arachne-delivery/` | Bounded publisher index, per-topic eviction watermarks, deterministic index snapshots, authenticated security/index bundles, authorized ranges and bounded signed recovery wire records | Crash-boundary validation, receiver cursors, retrieval and measured retention policy |
| `crates/arachne-security/` | Portable MLS owner, workspace credentials, invitation/admission transactions, encrypted snapshots, application protection and bounded author-signed recovery offers | Durable coverage indexing, transport repair, partition/revocation policy, runtime repair, selective-stream ratchet recovery and private audiences |
| `crates/arachne-node/` | Direct authenticated QUIC pub/sub, bounded queues, authorized return-address hints, explicit direct/LAN/WAN profiles, and a private connection module separating endpoint/address/dialing concerns from routing | Sparse dissemination, device-wide connection budgets and retained delivery |
| `experiments/` and `scripts/` | Reproducible host/Android connectivity and integration gates | Full product-level validation |

This inventory is intentionally separate from the target decomposition. A proposed or draft module is not runtime proof. [STATUS.md](../STATUS.md) is the authoritative build/verification handoff; [the node contract](../crates/arachne-node/README.md) documents the current callable API and limits.

## Android persistence boundary

The Kotlin coordinator holds an exclusive endpoint credential lease. Rust owns
the encrypted workspace record database and atomically saves staged security and
delivery changes before adoption, network replies or application release. JNI
receives temporary root bytes from the Android Keystore-protected identity;
both sides clear those bytes after the storage operation. Welcome payloads use
the binary JNI argument rather than expansion into JSON byte arrays.

A workspace database or durable backend marker selects native restore. A missing
or invalid selected database fails closed; a stale legacy snapshot cannot replace
it. An existing database without a marker is authenticated before repairing the
marker. Legacy active and pending state migrates when opened; legacy terminal
removal remains terminal. Native pending state preserves the original join
identity and request. Route selection and unknown-outcome pins remain in the
local catalog. Whole-database rollback protection still requires an external
trusted anchor; atomic commits alone do not provide it.

## Failure and resource model

Endpoints can crash, sleep, change address or remain offline. Networks can partition, reorder or drop traffic. Authorized participants can submit unauthorized operations; discovery and relay services can lie about reachability or deny service. Resource exhaustion must be bounded before parsing, decryption, queued delivery and replication work grow without limit.

Each endpoint needs limits for connections, concurrent work, frame sizes, queued bytes, retained bytes, retries and control history. High-rate latest-value data should coalesce rather than exhaust memory. Expensive bulk transfers must not starve management or interactive traffic.

A sparse overlay and scoped interest are the intended direction for larger workspaces. Thousands of members cannot imply thousands of persistent sockets on every phone. Workload and measurement requirements are in [Connectivity and scale](connectivity-and-scale.md).

## Architecture decisions still required

- Member/device credential binding and recovery.
- Group protocol, management authority and partition finality.
- Qualification and operating policy for replaceable discovery, relay and
  retention helpers under [the accepted service boundary](optional-services.md).
- Dissemination substrate and sparse-neighbor topology.
- Device-wide connection and dialing budgets across active workspaces.
- Publication envelope, delivery classes and history policy.
- Authenticated native ATAK bridge and workspace-aware contact/object mapping.
- Workload, capacity and supported device/network limits.

The [roadmap](roadmap.md) orders these decisions against the first usable demo. Research notes are supporting evidence rather than prerequisites for understanding this architecture.

## Semantic filtering boundary

Application adapters interpret their data taxonomy and project filterable
attributes. For ATAK this includes CoT type hierarchy, affiliation, entity kind
and location. Generic subscription/routing machinery evaluates supported topic,
attribute and geographic selectors without importing CoT or Android types.
Application profiles supply happy defaults; advanced publication and subscription
controls narrow each direction independently within workspace permissions.
The detailed filter protocol remains unimplemented and unselected. See
[Data and delivery](data-and-delivery.md#defaults-and-selective-pubsub) for the
standing-query examples, movement/staleness requirements and privacy boundary.

## Optional web management client

A hosted dashboard can provide future workspace onboarding and administration
through the portable security interface. Authorization is tied to its explicitly
granted workspace credentials, not to its hosting location or possession of a
web session alone. Receivers enforce the same policy used for ATAK requests.
The dashboard must not become a mandatory runtime authority. Key custody and
browser/backend topology remain future design choices; see the roadmap.

### Local workspace lifecycle implementation

The Kotlin WorkspaceConnections composes one WorkspaceController per connected
workspace. Each controller serializes its own membership, persistence, delivery
and feed operations. Selecting an already connected workspace keeps its owner
running. Navigation selects only the viewed workspace. Saved per-workspace
broadcast choices select zero, one or several outgoing ATAK PLI/map scopes; new
connections default to sharing. Inbound data continues to reach each connected
workspace independently. Disabling broadcast sharing does not disable receiving
or explicitly addressed native chat. Disconnect retains the sharing preference.
Direct and ATAK-created group conversations keep their selected recipient scope.
Publishing requires the producer's captured
workspace ID and never falls back to the current selection.

WorkspaceAdapters maintains one CoT/chat/feed adapter set per connection and
registers one aggregate native broadcast observer. Pause immediately removes only
that workspace from publication admission and adapter routing, then closes its
owner after accepted work drains. The UI reports Pausing until the controller
worker terminates and session cleanup succeeds. Failed cleanup stays visible
and prevents resume. Other workspace owners continue running. View reads local
presentation without creating an owner; Resume explicitly opens the saved
membership. Sharing and feed preferences remain stored across pause/resume.
On plugin startup, saved memberships are inactive until explicitly resumed. Monotonic view revisions prevent
out-of-order owner callbacks from restoring an older selection or disconnected
scope; closed adapter collections reject late binding callbacks.

Workspace group presence is independent of ATAK location and application-topic
subscriptions. Active owners announce through authenticated control on activation,
accepted membership changes and default-network return. Five-second refresh rounds
repair missed notifications. The current implementation uses direct fanout with
at most 16 requests in flight; a gossip overlay and large-workspace convergence
are not qualified. Presence observations expire after 15 seconds without fresh
evidence and are never restored from disk. The Members page distinguishes unknown,
recently reachable and stale presence while retaining authorized offline members.

Each notification is checked against its exact workspace and currently admitted
transport identity. Rust consumes the authenticated presence frame in the native
control drain, compares the membership and workspace-name heads, and starts the
bounded inquiry without a Kotlin peer walk or retry timer. Rust verifies the
signed record/checkpoint, then stages, durably commits and adopts the candidate
inside `drive_workspace`; the adapter receives a projection such as
`membership_replied`, `workspace_name_committed`, `workspace_name_peer_behind`,
`workspace_name_conflict` or `workspace_name_unavailable` and only renders it.
A verified incoming notification also refreshes the observed direct return
address. Presence does not authorize a member, publish PLI, rewrite map
timestamps or reconcile a conflicting membership branch. A conflict or stale
peer therefore leaves the local durable name unchanged and exposes a stable
diagnostic outcome.

Each workspace has a distinct credential slot, endpoint and member identity.
Rust-sealed state is saved before its catalog record or successful creation is
reported. The catalog stores a local display name, slot and expected workspace
ID; it does not authorize membership. An interrupted write can leave an unlisted
record; no orphan recovery interface exists. Signed member profiles are verified
against accepted membership, independently of ATAK callsigns and display names.
Older snapshots without the required profile fail to open; no migration is
implemented.

The saved catalog currently permits eight entries. The composition permits seven
owners, reserving one native runtime slot for the development endpoint. Closing
owners are awaited during shutdown. Connections are explicitly reopened after
restart; the connected set is not persisted. These are prototype capacity limits,
not a claim of workspace or participant scale. Concurrent delivery has an Android instrumentation check and actual ATAK
evidence for scoped native PLI and ATAK direct/group conversation histories (see
STATUS.md). Reusing a native point across workspaces and independent disconnect have
ATAK evidence too, including native object-list cleanup. Broader identity privacy,
scale and internet behavior still require their own evidence.
