# Domain model

The data fabric lets people and services collaborate in isolated workspaces without operating a central collaboration server. Participants publish and subscribe to application data through local endpoints. ATAK is one application adapter; a sensor feed or another application uses the same fabric concepts.

This document defines the product's entities, relationships, lifecycle rules and invariants. It describes the target model, not a claim that every behavior is implemented. [Architecture](architecture.md) explains how the model is realized; [the glossary](../CONTEXT.md) defines the shared terms.

## Workspaces and participants

A **workspace** is a collaboration and authorization scope. It has an identity independent of its display name, memberships, administration policy and scoped topics. Renaming a workspace must not create a new security identity. Two workspaces with the same name are still separate.

The creator chooses a human-readable workspace name, such as “Search and Rescue” or “Training Team”. Members see that shared name during onboarding and in their workspace list. Workspace naming is separate from member naming and ATAK callsigns. Names do not authorize admission; an invitation’s advertised name is untrusted until bound to authenticated workspace metadata. Shared name changes require workspace administration authority and must preserve the workspace identity. Internal IDs and test-run labels are not default display names.

Name and membership convergence is a Rust-owned transition. An authenticated
presence head may start a bounded inquiry; Rust verifies the signed record or
checkpoint, stages it, durably commits it and adopts it before projecting the
result to an adapter. A peer behind or an equal-revision conflict is reported as
a stable recoverable outcome and leaves the local accepted name unchanged. A
display adapter must not replace this with a peer walk, retry timer or second
save/adopt state machine.

A **member** is a participant admitted to a workspace. A participant may be a person using ATAK or a service publishing observations. **Membership** records that participant's relationship to one workspace: allowed actions, role and relevant authorization state. Membership in one workspace grants nothing in another.

An **endpoint** is a running fabric client on a device or service. It has authenticated connection credentials and acts within the permissions granted to it. A member and an endpoint are distinct: a transport key identifies a connection participant, not necessarily a person. The ownership, linking and recovery rules for multiple devices representing one member remain a design decision. The model does not require a global account provider.

An **administrator** is a workspace role authorized to perform specified management actions. A workspace supports multiple administrators. Its creator is not a permanently required coordinator, and being an administrator does not require staying online. Service/feed participation does not automatically grant administration rights.

| Relationship | Meaning |
| --- | --- |
| Workspace → memberships | Admission and permissions belong to a specific collaboration scope |
| Membership → roles and permissions | Administration, publishing and reading are separate capabilities |
| Member → authorized endpoint credentials | A verified binding allows an endpoint to act for a participant; binding policy is still to be specified |
| Workspace → topics | Identical topic names in different workspaces identify different routes |
| Endpoint → subscriptions | Each endpoint expresses its current interest within its authorized scope |
| Publication → author and recipient scope | Origin and intended audience remain meaningful even when intermediaries forward the data |

A routing table may use endpoint-key permissions as a projection of membership state. That table is not the authoritative member registry: it cannot decide whether a person may add a device, whether an administrator was demoted, or whether an invitation was valid.

### Direct recipients

A **direct recipient scope** is a nonempty canonical set of current workspace
member identities. It belongs to a publication, is authenticated with that
publication, and is resolved to workspace-facing endpoints from the accepted
roster. It is never inferred from an IP address, ATAK UID, callsign, display
name, selected screen, or a topic subscription.

The current membership model binds one endpoint to a member in a workspace.
That is an implementation constraint, not a claim that a human can own only one
device. When multi-device membership is introduced, recipient resolution must
return the accepted endpoints for that same member identity without changing the
meaning of a direct publication.

A direct publication and a topic publication have different audiences:

| Publication kind | Audience is selected by | Required outcome when selection fails |
| --- | --- | --- |
| Topic publication | Authorized current subscriptions | No implicit workspace-wide fallback |
| Direct publication | Authorized current subscriptions intersected with its authenticated member scope | Report non-delivery for unsubscribed targets; never convert to a topic broadcast |

The recipient member identities and the resolved endpoint identities serve
different roles. Member identities express the user/application intent and are
stable while an endpoint remains a current workspace binding. Endpoint
identities identify the authenticated Iroh connection that carries this one
delivery. The adapter may map a native ATAK contact UID to a member identity,
but that map is local, workspace-scoped presentation state and never authority.

## Local workspace activity

A participant can join multiple workspaces and use several concurrently. Each
workspace has independent local activity (active or paused), desired publishing
choices and desired subscriptions. The workspace being viewed is a navigation
choice, not authority to change those traffic choices.

The Rust runtime owns the durable workspace lifecycle: a join attempt or joined
workspace progresses through staging, durable commit, adoption, retained reply
and terminal removal there. Its durable `WorkspaceActivity` projection is the
single phase/reason source for adapters. An adapter owns only its local
application binding, requested activity and rendering of that projection; it
must not recreate lifecycle ordering or infer a competing state machine.

Pausing a workspace preserves membership, scoped credentials and desired settings.
It suspends local activity for that workspace without pausing others or announcing
other memberships. It is distinct from leaving, removal and accidental loss of
connectivity. The UI must distinguish a requested pause still draining work from
a completed pause. No new publication may be admitted to a completed paused
workspace as though it were active.

Resuming uses the same membership and restores its desired settings subject to
current accepted authority, retention and freshness rules. It does not silently
rejoin, undo removal or promise delivery of expired/missing history. Work produced
while paused must be rejected visibly or explicitly identified as pending; it
must not be represented as delivered.

For example, a participant can receive a feed in Operations while exchanging
chat in Training, pause Training, and keep Operations running. Opening Training's
member page need not resume it or redirect outgoing map broadcasts. Publishing
the same source into multiple workspaces is an explicit local choice, never an
implicit bridge for data received from another workspace.

A **nearby advertisement** is a device-scoped, bounded and expiring projection
of one workspace invitation. It is not the workspace, membership, invitation
authority or endpoint discovery itself. A device may advertise several
workspaces at once; each advertisement has its own workspace, mode, invitation,
expiry and enabled state. Discovery returns an untrusted selection hint. The
joiner must still authenticate the invitation and verify the workspace before
joining. Stopping one advertisement must not stop the others.

## Identity boundaries

### Local application bindings

A **local application binding** associates one application's native collaboration
context with one workspace. Several native operations can use that same binding;
their requests still obey workspace membership, recipient and subscription rules.
The binding is adapter-owned and is not a fabric endpoint or administrator.
Non-ATAK participants do not need an ATAK binding to use the fabric library.

Applications may retain references to a binding while a workspace is paused or
offline. Resume must restore the same association; it must not present the old
context as a different workspace. Local credential renewal or a change in peer
routes does not change that association. A paused or removed workspace admits
no new operations through its saved binding, and closing one binding must not
interrupt another workspace's native operations.

Native application objects remain distinct from the binding and workspace. For
example, a Data Sync mission belongs to the ATAK adapter's application model;
it is not automatically a workspace, workspace membership or fabric feed.

The ATAK adapter implements this association with a saved, device-local loopback
host per workspace and a stable native stream port. The address registry contains
no group or transport keys. Session credentials can rotate independently.
An occupied or invalid binding is a connection failure, not permission to replace
another native connection or silently assign a different workspace context.
See [the binding decision](adr/0002-stable-native-workspace-bindings.md).

### Workspace and application identities

The following identifiers serve different purposes and must not be interchangeable:

| Identity | Identifies | Does not establish |
| --- | --- | --- |
| Workspace identity | A collaboration/security scope | That a similarly named workspace is trusted |
| Member identity | An admitted participant | Which current device keys may act for it without a binding |
| Endpoint identity | An authenticated fabric endpoint | Workspace membership or administration |
| Publication identity | A particular submitted item for deduplication and receipts | That its author is authorized or its contents are accurate |
| Application entity identity | A tracked object, feature or other application entity across its native application | Fabric credentials or publication authority |

An ATAK callsign is a display label. An ATAK UID belongs to the adapter's application model and stays stable when the same CoT entity arrives through overlapping workspaces, matching ATAK's UID-keyed update model. Neither authenticates a fabric member. The adapter separately maps that UID to an authenticated member within each workspace when resolving recipients.

### Membership privacy

A device may participate in multiple workspaces without announcing that fact to
any of them. Each workspace sees separate endpoint and member credentials. A
device is therefore not synonymous with one globally visible endpoint identity.
Any local relationship between these identities stays local; a common public
root credential, device identifier or directory entry must not reveal it.

Invitations, peer discovery and management responses reveal only the relevant
workspace context. Application payload identity is separate from this security
boundary. ATAK event, contact and reference UIDs remain stable inside encrypted
authorized delivery so ATAK can merge paths and edits correctly; they reveal no
other workspace roster, endpoint credential or membership authority.

This provides separation of protocol identities, not anonymity. Shared IPs,
timing, callsigns, locations or identical application content can correlate
participants. User-visible identity choices and published content remain
meaningful; the fabric must not claim to conceal what the participant publishes.

## Admission and invitations

An **invitation** is a scoped capability to initiate admission to a workspace. It provides a way to authenticate the intended workspace and find possible peers. A QR code and a link are encodings of the same invitation, not different membership mechanisms.

The conceptual admission flow is:

1. A joiner receives an invitation and checks its format, validity and workspace authority.
2. The joiner discovers a reachable endpoint and authenticates the connection independently of its address.
3. The joiner presents credentials and requests the permitted membership.
4. An open invitation supplies approval in advance. A personal invitation requires an administrator to approve the recipient's exact saved join request. Once that approval is shared, a reachable current member can facilitate the join while administrators are offline.
5. The membership operation becomes accepted under the workspace's coordination policy.
6. The accepted result remains available until the requester retrieves its reply.
7. The endpoint acquires the required cryptographic state and becomes ready for its permitted data operations.

A **join attempt** preserves its intended workspace and proposed member identity while pending, including across a restart. A rejected response must not silently replace that identity. Becoming ready requires accepted membership and safely persisted group state; retiring pending work must not precede saving the accepted result.

For a compact invitation, Rust keeps the bearer, request identity, bootstrap
endpoint IDs and selected-peer cursor in the encrypted native pending snapshot;
the Android adapter stores only catalog/progress metadata and supplies optional
address hints. Rust asynchronously obtains the signed checkpoint, retries the
persisted peer set without a host timer, and owns stage, durable commit and
adoption. The work signal wakes an adapter to render the projection. Reset and
cancel abort the native exchange before clearing pending and regular records.

An older invitation may precede later membership changes. A reachable member must
supply the authorized transitions from the invitation's trusted state to the
accepted admission; the joiner verifies that chain independently. Missing or
conflicting history must be resolved before creating an admission that the joiner
cannot validate. Supplying history does not grant the assisting member the right
to issue invitations or change administrator roles.

If a join request may already have reached a peer, a lost reply leaves its outcome
unknown. Changing peers must not silently create a second, competing admission.
The join attempt retains its identity and seeks the existing outcome; an endpoint
that failed before transmitting the request is a different case. The selected
peer and uncertainty must survive restart. A later failed connection cannot erase
an earlier unknown result. Invitations can carry routes for other admitted members;
those hints identify possible paths and never grant authority.

These steps can wait or fail independently. A reachable peer is not a successful join; an administrator's approval is not necessarily a finalized group transition. The UI should distinguish connecting, awaiting approval, synchronizing and ready.

Concurrent join attempts may be acknowledged as pending and then accepted one
at a time under the workspace's membership policy. The owner must not replace
an uncommitted candidate with another request. After one membership is accepted,
its retained result can be retrieved while another candidate is being prepared.
Reply loss therefore does not require rolling back accepted membership or
blocking unrelated join attempts; the requester retries the same admission
attempt.

An admission attempt is the durable, retryable unit for one join request. Its
stable identity is scoped to the workspace and is derived from the authenticated
transport endpoint plus the exact signed request bytes. Display names, routes,
connection paths and retries are not attempt identity. Its queued,
approval-pending, committed, reply-retained, adopted, ready, rejected, canceled
and unknown outcomes are distinct evidence.

Approval-pending attempts are retained by the Rust runtime rather than only by
the host UI. The host may page the bounded registry, acknowledge that an item was
shown, and approve or decline by attempt ID. Applying a membership transition
elsewhere re-evaluates the same attempt on retry; an obsolete pending projection
must not block an approved or declined request.

The lower Rust security library owns the attempt model, bounded owner-side queue,
request validation and cryptographic transition seam. Hosts such as Android/ATAK
adapt transport and persistence around it; they must not reimplement admission
identity or deduplication. The requester persists the attempt. The owner's queue
is a bounded process-local projection that can be rebuilt by retrying the same
attempt after restart.

Cryptographic membership commits may be serialized, but queue acknowledgement and
retrieval of an already-retained result must not wait for an unrelated attempt to
finish. Supporting a large simultaneous event requires batching compatible adds
at the lower MLS seam; increasing the host queue alone does not provide that
capacity. The lower library can group up to 128 independently validated
ordinary-member Adds into one MLS transition, retaining one shared commit and
Welcome with one authorization result per attempt. The current JSON transport
adapter deliberately batches at most 16: a 16-member membership offer is 30,610
bytes under the 32 KiB request bound, while 24 members is 45,299 bytes and
fails. The batch size is bounded by measured wire envelopes and phone-memory
limits, not by the invitation QR/link size. The runtime pages authenticated
history under the 128 KiB control-reply budget, so a 500-member burst can be
verified without one giant response. The proof verifies history in 64-step chunks and rolls
over into a further chunk when a branch is longer, so an invitation pinned at
epoch 0 stays redeemable after hundreds of epochs. Rollover never widens a
chunk: one encoding, one control request and one reply page each still carry at
most 64 steps, and the joiner replays every chunk from the pinned checkpoint, so
a rolled-over anchor cannot stand in for membership verification. The pinned
invitation/checkpoint itself is still bounded by the control request budget.

Admission intake does not pay for that branch twice. An owner verifies each
membership commit once, when it accepts it. When an arriving request pins a
checkpoint the owner itself issued and retained with its authenticated
invitation transition, the transitions it serves come from its own accepted
records rather than from replaying the branch commit by commit, so per-request
intake cost stays flat as the group grows: measured 42 ms at the 5th admission
and 45 ms at the 60th, against 53 ms rising to 1.42 s when the branch was
replayed per request. Retention is durable, so a restarted owner keeps the same
cost. This is not a cache of a verification result and it skips nothing that is
per-request: the request decode, invitation-controls check, issuer authority and
endpoint binding are evaluated on every admission, an unretained or altered
checkpoint falls back to full replay, and accepted records that disagree about
an epoch fall back rather than guess.

An invitation does not contain a permanent shared traffic key. Expiry, revocation, use limits and scope must be verifiable. Globally single-use invitations across disconnected partitions require coordination; the product must not display that guarantee unless the chosen mechanism provides it.

The current implementation offers open and personal links, with no global use
counter. Personal approval binds the hash of one signed recipient KeyPackage in
the accepted workspace policy. A copied link cannot substitute another package.
A retry must recover the original admission rather than add a second member.
Ordinary members can facilitate joins but cannot issue, approve or disable links.

Creation, approval and disable are authenticated administration transitions. The
host saves each transition before displaying the result or sharing its output.
An accepting peer enforces the policy it has received. Disconnected peers cannot
enforce unseen disable/approval changes; administrators should synchronize with
available members before disconnecting. With one administrator and no other
admitted member online, a prospective joiner keeps their saved request and waits.

Expiry is evaluated against the accepting device's clock for new requests. It is
not a trusted global timestamp or retroactive expiry of accepted membership.
Historical proof checks the link's accepted policy and exact recipient binding
without rejecting earlier valid joins merely because time has passed. A peer
with a wrong clock can enforce the wrong wall-clock deadline. The demo does not
claim strict distributed time or instantaneous revocation across partitions.

The existing bounded history and fork-recovery constraints still apply. Event
links remove repeated human approval; they do not establish large-event capacity.
Rejoining after a terminal local record and deleting saved cards remain separate
work from ending membership.

## Membership and administration lifecycle

Membership has an authorization lifecycle, while endpoints have an independent reachability lifecycle. An active member can have no reachable endpoint. Going offline does not revoke membership; coming back online does not restore revoked authority.

| Action or condition | Required meaning |
| --- | --- |
| Admission | Establish membership through authorized policy and cryptographic transitions |
| Leave | End your own membership through an authenticated departure; a sole member can end locally |
| Permission change | Change allowed actions without treating every change as a new identity |
| Promotion or demotion | Grant or remove management authority according to policy |
| Endpoint loss or key rotation | Change device credentials through a verified binding/recovery process |
| Revocation | Exclude the removed authority from subsequent operations and key access once the change is accepted and known |
| Re-admission | Require an explicit authorized action; stale state must not silently restore removed rights |
| Offline return | Reconcile supported authorization and cryptographic dependencies before resuming operations |

For a team, leaving is signed by the departing member against the current
membership branch and committed by another admitted peer. That peer cannot forge
someone else's departure. A sole administrator must first promote a successor
before leaving a nonempty team. A sole member needs no peer. Saving the terminal
outcome precedes closing native destinations; reopening it cannot resume sharing.
An interrupted attempt retains recoverable membership until the outcome is known.

An accepted removal has a durable local outcome. Reopening its **removal record**
must show the ended membership rather than reconstruct an active participant.
A surviving member and the removed member therefore receive different local
results from the same authorized action. Returning later requires the explicit
re-admission policy; going online or reopening the workspace is not re-admission.

A **management action** targets a member's stable workspace identity, never its
display name. Promotion, demotion and removal are distinct intents. A receiver
must verify the exact effect rather than treating one authorized action as
permission to replace the entire administrator list or change unrelated policy.
Removing an administrator must remove both its membership and management role.
A role change must not accidentally remove membership. The local acceptance of
an action does not prove that disconnected peers have learned it.

Multiple administrators may issue concurrent actions. A disconnected administrator can lack knowledge of a demotion, and two partitions can contain conflicting changes. The system needs explicit rules for when an operation is pending, effective or final, and what happens on reconciliation. Those rules are not determined by the administrator role alone.

**Unresolved policy:** whether membership changes pause during partitions or may take effect independently within a partition, and how conflicting operations become final. Ordinary permitted data exchange among existing reachable members should not depend on one particular administrator remaining online.

## Topics, permissions and subscriptions

A **topic** is a workspace-scoped category for routing publications. Applications may use topics for position updates, shared features, chat or sensor observations. Topic naming does not determine payload format.

Permissions distinguish publishing, subscribing/reading and management. Requesting a subscription only expresses interest; it grants no access. Membership does not imply subscription, and publication must not fall back to sending to everyone when there are no interested recipients.

A subscription can be withdrawn or invalidated by a permission change. Regranting permission must not silently restore an interest that was removed by revocation. Persistence and reconciliation of desired subscriptions across reconnect need a defined policy.

A topic is also distinct from a **cryptographic group**. Topics with the same authorized readers may share a protection context. Different confidential audiences require appropriate cryptographic separation. A topic filter alone cannot prevent a holder of a shared symmetric key from decrypting content.

## Publications and delivery

A **publication** carries application data within a workspace and topic. Its semantic contract includes an authenticated author, intended recipient scope, a stable identity for retries/deduplication, payload type/version and appropriate freshness information. The exact wire representation is a protocol choice.

A publisher sequence orders publications from one author within a workspace and
cryptographic epoch. It does not establish order across authors or workspaces,
application delivery, or the absence of unselected publications between two items.
A sequence claim must be authenticated before it can justify accepted progress.
Publications without such evidence have unknown authenticated order; assigning
them positions from arrival time or a local cache does not supply that evidence.

The immediate transport peer may be an intermediary. Forwarding must preserve verifiable authorship and must not confer the relay's privileges on the original author. An authorized sensor publisher proves which participant submitted an observation; it does not prove the external observation is true.

Delivery states describe distinct evidence:

| State | Evidence it represents |
| --- | --- |
| Locally accepted | The local fabric accepted responsibility under a declared queue/retention policy |
| Admitted by peer | A peer accepted the operation at its stated processing boundary |
| Replicated | Another holder acknowledged retaining the item under a specified policy |
| Delivered to application | A recipient application accepted the item |
| Read | An application-specific user action, if that application supports it |

A timeout can leave an outcome unknown. Retries need the same publication identity and duplicate handling; they must not imply exactly-once application effects. Delivery to one recipient says nothing about the others.

Different data needs different treatment. A position update may expire or replace an older pending value. Chat may need bounded retained delivery. A shared feature may need application revision/conflict rules. Large content may be referenced by a publication and transferred separately. These policies are detailed in [Data and delivery](data-and-delivery.md).

### Fabric exchanges and transport efficiency

A **fabric exchange** carries one bounded publication-admission, control or
retrieval interaction. It has a purpose, authenticated peer, applicable workspace
and authority context, and an outcome. An exchange is not itself a publication:
retrying delivery or fetching a replica must preserve the original publication
identity, resource hash, author and recipient scope. Transport representation
must not redefine signed content or create a new application effect.

| Concept | Owns | Must not imply |
| --- | --- | --- |
| Publication / resource | Application meaning, author, identity, audience and declared data policy | A particular encoding, route or connection |
| Fabric exchange | One bounded interaction and its result or uncertainty | Application acceptance, exactly-once effects or new authority |
| Peer connection | Authenticated endpoints carrying compatible exchanges | Permission cached for the lifetime of a connection |
| Peer path | Observed direct/relay route, validation and timing | A membership change or successful delivery |
| Workspace state summary | A peer's scoped state-comparison claim | Finality, completeness or permission to adopt state |
| Traffic observation | Measured work/bytes at a stated layer and interval | Unmeasured causes, billing totals or delivery receipts |

Connection reuse stays within the same workspace-facing credentials and
compatible protocol. A common IP, device or member display name must never
collapse separately scoped identities into one publicly linkable connection.
Each admitted exchange rechecks current accepted authority and subscription or
recipient constraints. Keeping a connection open cannot keep removed rights
alive. Reuse does not require a maintained connection to every member; it remains
subject to connection, dialing, concurrency and queued-byte budgets.

Connection budget and exchange capacity are separate: an idle connection does
not occupy an active-exchange slot, and data traffic cannot consume the control
reserve. Per-endpoint bounds are not a shared device-wide connection budget.

The host owns one cloneable `ConnectionBudget`; each workspace endpoint retains
its own identity, authorization and connection cache. The native session registry
shares that budget across its sessions. Default device limits are 64 established
data/gossip links and 512 control links, 16 data/gossip dials and four control
dials, 512 incoming handshakes, and 32 data/512 control exchanges. These are
separate bounds, not a claim that handshakes are application exchanges. Native
gossip uses the same data-dial permits as direct traffic. A queued native dial
does not consume a dialing permit or emit network traffic until admitted.
Completion, failure, cancellation and endpoint shutdown return capacity;
connection-close accounting uses weak handles and cannot keep a link alive.

Finishing one exchange releases its own resources, not those of unrelated
exchanges on that connection. A path change alone is not a reason to replay an
operation. If a connection fails after transmission, its outcome can remain
unknown: retries follow the operation's existing identity and recovery rules,
not a generic replay-on-reconnect rule. Pausing or leaving a workspace stops new
exchanges under its existing lifecycle contract without affecting another one.
An abandoned or expired control reply is a failed exchange with a possibly
unknown application outcome, never an implicitly successful empty reply.

State comparison and state transfer are separate. An unchanged, scoped summary
can avoid sending the same verified history or profile repeatedly. Reconnect,
changed summaries and an explicitly bounded periodic reconciliation still need
to recover lost notifications. Equal epoch numbers alone never prove equal
membership branches; names, profiles and catalogs have their own comparison
scopes. A missing or conflicting base requires authorized full-state recovery,
not silent acceptance of a delta or a claim of freshness.

Membership comparison carries the local epoch, epoch fingerprint and workspace
name head. A pending reply is discarded if that accepted local basis changes.
The presentation-profile summary hashes the workspace, epoch fingerprint and
sorted verified profiles; it is only a comparison hint, never membership or
profile authority. Equal sets omit records. Changed or lost sets reconcile with
bounded signed-profile pages on the existing periodic exchanges, including after
either participant restarts. Signed membership/name/profile records keep their
existing validation. The compact membership exchange and presence packet are
the single current version-1 schemas, without historical decoding branches.

Wire encoding is lossless; a smaller encoding must recover exactly the original
protected bytes. Efficiency preserves each declared data policy. Latest-value publications may
replace superseded queued values only for the same authorized selection and
entity, without renewing an expired value. Retained events cannot be discarded
as duplicates merely because their payloads match. Resources remain immutable,
hash-verified content; catalog advertisements and replica claims do not repeatedly
transfer the content or authorize installation. Large transfers must leave room
for control and interactive exchanges.

Resource transfer is distinct from publication delivery. Protected messages carry
descriptors, replica claims and recipient-bound read grants. Immutable bytes
stream on the fabric's existing authenticated data connection. Accepted
membership resolves member to endpoint identity. Providers check the bound
endpoint, current workspace policy and exact blob; revocation also interrupts
active streams. Content-addressing is integrity, not authorization. The standard
blob engine verifies resumable ranges; the consuming adapter verifies its full
descriptor hash and length before returning or advertising a complete file.
ATAK's SHA-256 identity and URLs are adapter projections, not a second transport.

There is no configured or hard-coded resource-size ceiling. Stream buffers,
concurrent work, disk headroom and user-selected replica quotas are distinct
bounds. One unfinished transfer per workspace may retain verified partial bytes
for resume; replacing or clearing that partial reclaims obsolete storage before
another download. A partial is never offered as a complete replica or installed.

Traffic observations distinguish original application bytes, encoded exchange
bytes and transport bytes, including repeated transmissions where observable.
Counts specify local workspace/peer scope, direction, interval and session reset.
Forwarded copies, retries and protocol traffic are not additional unique
publications. Unattributed transport bytes remain unattributed; a relay-to-direct
transition does not prove why bytes were spent or reset their accounting.
Diagnostics expose bounded local observations, never plaintext payloads,
credentials or other workspace memberships.
Peer troubleshooting distinguishes known addresses, attempted paths, validated
paths and the selected path. Missing failure evidence remains unknown; a relay
selection alone does not diagnose filtering, exhausted retries or a broken peer.

The portable fabric owns these contracts for all adapters. Binary encoding,
connection reuse and summary scheduling are implementation choices below that
interface; changing ATAK settings is not a transport optimization. See the
[wire-representation decision](adr/0006-compact-peer-wire-preserves-domain-records.md).

### Continuity and gaps

Continuity is evaluated within an exact scope, not across every publication in a
workspace. A useful scope must account for the source history, the interval in
which the receiver was authorized and interested, recipient restrictions and the
declared data policy. A workspace status can summarize several such scopes, but
there is no implied total workspace order.

A later sequence can make a missing publication suspicious, but it cannot confirm
loss by itself. The unseen position may belong to another topic or audience, may
have arrived out of order, or may predate the receiver's subscription. Confirming
a gap requires authenticated coverage evidence that preserves those distinctions
without disclosing restricted publication activity.

The fabric can establish publication continuity while the application decides
what a gap means to its state. A retained event may be replayed. A latest-value
feed may need a fresh replacement and an indication that samples were skipped.
A shared object may require a snapshot or conflict-aware synchronization. A bulk
resource may require missing chunks. Membership and policy history must follow
its authority and cryptographic rules rather than an application replay cursor.

Gap detection, availability, repair and application acceptance are separate
outcomes. A confirmed gap can remain unavailable when no authorized holder has
the data. Successful repair accounts for the declared data policy; it does not
mean a person saw the information or that the source observation was correct.

A pending application delivery is not a publication gap: its receive record is
already durable. A retrying or unavailable application must not stop admission
of other eligible publications, gap discovery, peer recovery or presence.
Application acceptance advances independently of recovery progress. Pending work
keeps its stable identity until acknowledged or explicitly rejected; a transient
failure is neither acknowledgement nor permission to discard it. Membership
transitions must still preserve accepted pending work under its original scope.
Retry deferral applies to the whole application delivery stream, not an individual
packet that later packets may overtake. Independent streams may proceed while
that stream waits. Deferral is local scheduling, never accepted coverage, rejection
or permission to erase the pending record.

An entity change is not necessarily a replaceable value. Omission, assignment
and explicit removal follow the consuming domain's rules. A later position-only
change cannot supersede an earlier metadata change merely by arriving later.
Compaction is valid only to a complete entity checkpoint that preserves the
effects of accepted changes through a stated coverage boundary. Original changes
may remain available for historical processing under the retention policy;
historical observations keep their original time and expiry and cannot become
fresh live state by replay. Deletions and ordering apply to recovered changes as
well as live ones. These semantics belong to each adapter, not a generic XML
merge or a payload-aware fabric core.

Coverage authority, possession and transfer are also separate. The original
publisher or a data-specific replicated-state protocol establishes what belongs
in a scope. Any authorized replica holder may advertise possession and serve the
unchanged verified publication while the publisher is offline. The receiver
verifies the original author and scope after transfer; the holder does not acquire
permission to rewrite history, widen the audience or claim that no newer data
exists.

“Current” is defined by the declared data policy. For a latest-value feed it may
mean the newest authorized, unexpired value known within the coverage boundary.
For shared state it means convergence by that state's version and conflict rules.
For retained events it means accounting for the required sequence. For
membership it means the accepted authority history. No generic counter or newest
arrival can establish one ideal workspace state across all four.

## Offline state and recovery

A shared resource is an immutable content snapshot offered within a workspace.
Its resource descriptor is the replicated catalog fact: content identity,
author, size and application metadata. A descriptor does not imply that bytes
are present anywhere. A replica claim is separate, authenticated state about a
member endpoint's complete verified copy and may disappear without deleting the
descriptor.

Catalog storage preserves each resource offer under its authenticated publisher
and content hash. The browse projection merges identical content, but a
publisher's tombstone removes only that publisher's offer. Removed members'
offers are not listed. Names and claimed publication times are presentation,
not authority; the offer publisher is not necessarily the original file creator.

Retention intent is local policy. It can opt a workspace or selected resources
into byte retention under a bounded quota. Eviction deletes only the local copy,
withdraws that endpoint's replica claim, and preserves the descriptor. A partial
or hash-unverified file is never a retained replica and must never be advertised.

Automatic, selected-only and off are device-local retention choices, independent
of replica serving, application installation and workspace activity. Turning
serving off withdraws local replica claims without deleting verified bytes.
Explicitly published resources are owned copies, outside the replica cache
quota. Cache removal cannot target them or an application's installed files.
Resource length is distinct from retention quota and working memory. Transfers
stream through bounded buffers, check available storage and verify the complete
content hash. A large resource is not rejected merely for crossing a fixed
application upload cap. A stalled read can expire without imposing a fixed
total duration on a transfer that continues making verified progress.
Directed grants do not authorize workspace-wide catalog publication or caching
for redistribution. Unmarked native uploads stay staged until an explicit
public action; unsupported private-server semantics must fail, not publish.

A directed transfer tracks each intended recipient independently. Authenticated
activity means that the receiver still owns queued, fetching, verifying or
application-import work; it is not a delivery or installation receipt. Activity
renews an idle lease, never a file-size or whole-transfer deadline. A silent
recipient's expiry cannot terminate another recipient's active read. Final
application results are recorded once; late/duplicate results cannot turn a
failed or completed recipient into a different outcome. ATAK import completion
is separate from verified byte receipt and remains owned by ATAK's native task.

An authorized member may obtain a resource from an available holder; knowing a
hash or local URL grants no access by itself. Holder selection and
request/response correlation retain the workspace and member scope. Local
application URLs are adapter references, not addresses to send unchanged to
remote participants. Removing one holder's claim changes availability; it
cannot erase copies already obtained by another participant. A resource read
does not change the resource, so retrying a read must not create another
application object.

An application package is an adapter-level projection of a shared resource and
its resource descriptor. For example, ATAK maps the descriptor to a mission
package search result and maps retrieval to `/Marti/sync/content`. “Arachne:
<workspace>” is therefore an adapter presentation of a workspace capability,
not a fabric entity or a server role.

Offline delivery requires a retained copy that survives the sender's absence. A reachable holder may be another member endpoint or an optional encrypted storage helper. A receiver may query several eligible holders and accept the first copy that verifies against the expected author, identity and scope. If every holder is unavailable, retrieval waits; if all retained copies expire, the item is unavailable. Holder discovery must not reveal restricted activity to an ineligible member.

Application history and cryptographic recovery history have different purposes and retention constraints. An offline member may have ciphertext but lack the transitions needed to decrypt it. A newly admitted member must not receive historical group secrets merely as a side effect of ordinary synchronization.

Restart recovery must preserve accepted authorization state, key state and pending work consistently. An endpoint that cannot safely recover within the supported window needs a visible recovery or rejoin outcome, not silent rollback.

## Invariants

- No connection address, display name, subscription request or application UID grants authority.
- Workspace scope accompanies authorization, routing, storage and adapter identity mapping. Cross-workspace sharing requires an explicit action.
- Application administration policy governs management actions; cryptographic protocol roles do not silently inherit that authority.
- Receivers enforce permissions and cryptographic validity, even if a sender bypasses its own UI.
- Private recipient scope is cryptographic, not just presentation filtering.
- Revocation cannot erase plaintext already learned or be enforced by peers that have not received it.
- Expired retained position data is never presented as fresh live location.
- Crash recovery cannot reuse or roll back security state in ways forbidden by the selected protocol.
- No individual creator, administrator, directory or relay is a mandatory permanent authority for ordinary collaboration.

## Decisions required to complete the model

1. Member/device/service identity binding, rotation and recovery.
2. Administrator authority for invitation issuance, approval, promotion and removal.
3. Partition finality, concurrent revocation and re-admission rules.
4. Invitation replay limits and history available to newly admitted members.
5. Subscription restoration, publication retention and application conflict policies.

These decisions are tracked in [the roadmap](roadmap.md). Implementation progress and test results are maintained separately in [STATUS.md](../STATUS.md).

## Member names and application contacts

Every human or service member has a workspace-scoped profile with a chosen
display name. The member identity remains stable when that name changes. Names
need not be unique and never authorize an action, merge memberships or identify
a cryptographic recipient. A service can name itself without an ATAK callsign.

ATAK may prefill a person's proposed display name from the current callsign, but
the person can choose a different name for each workspace. The adapter maps each
workspace member identity to that member's stable native ATAK contact UID.
Overlapping workspaces therefore add authorized paths to one ATAK contact rather
than creating duplicate contacts. It renders
the member's chosen name, optionally overridden by a local contact alias. An
alias is private local presentation and does not rename the remote member.
Changes to the ATAK callsign do not silently replace the accepted member profile.

A cached profile is presentation evidence, not a membership record. Before showing
a cached name with a role, the client verifies its author against the accepted
workspace roster. Removal invalidates that association. A signature authenticates
a name's author; it does not prove that a cached name is the latest revision.

The on-device profile cache has no member-count limit. Each single file read stays
under a 128 KiB bound by paging the cached roster across multiple page files, not
by rejecting large rosters; a manifest file naming the current generation and page
count is the sole write commit point, so a torn write is read back as an absent
cache rather than a silently partial roster.

The owner's in-session profile cache (`arachne-runtime`, Rust) mirrors that design:
retention is bounded by total retained profile bytes, not a member-count constant,
so it grows with bytes/pages consistent with the paged Kotlin cache above rather
than capping at a fixed member count. A per-profile size bound (`MAX_MEMBER_PROFILE`)
and a per-request profile count (the wire/chunk bound each `member_roster` call
carries, mirroring Kotlin's chunked publication) both still apply; only the
cross-call retention cap was replaced. An oversized profile (exceeding
`MAX_MEMBER_PROFILE`) or an over-count batch produces a distinguishable error,
never a silent `Ok` that drops it unnoticed. A full retained-set byte budget is
different: it is presentation pressure, not a membership-control failure, so it
never errors a membership-control operation (`PollMembershipUpdate`,
`member_roster`/open, a peer reply) -- the merge retains whatever fits, drops
the rest, and the caller's reply carries a distinguishable `profiles_retained:
false` signal instead. Unverifiable profiles (author not on the accepted
roster, bad signature) are still dropped.

A profile announcement/update must be attributable to an admitted member and
accepted only within that workspace. A self-asserted name is not verified real-world
identity. Duplicate names remain distinct contacts and membership rows, with
workspace context and an identity-inspection affordance for disambiguation.
Member management must never require users to work with raw endpoint keys as
names. Admin-defined labels or managed renaming, if added, require separate
explicit authority; they are not implicit in a member's right to name themselves.

An ATAK entity/track is not necessarily a member contact. A feed member may
publish many independently named entities; the adapter must not rename every
published track after its publisher. Recipient selection resolves the mapped
member identity, not a name string or an unscoped native UID.

## Recovery offers and retained coverage

A receiver establishes the author, workspace, selection and required range from
its own accepted state. A retained-data holder cannot redefine that expectation
to match whichever records it happens to have. An authenticated recovery offer
binds the publisher to a particular ordered set within that request; the holder
must return that set intact before the receiver adopts cryptographic progress.

The publisher is responsible for the correctness of its retained index. Verifying
its statement detects a holder's omissions and substitutions, not dishonesty by
the publisher about its own history. An unavailable range must remain distinguishable
from completed recovery. Reusing an offer for the same historical range is allowed;
it is not evidence of newer coverage. Publication access rules still apply, and
recovering private data cannot widen its audience.

A publisher cursor and selected topics define the history a receiver is requesting.
Retained coverage is evaluated for that selection. Losing unrelated feed history
does not imply losing retained chat, while forgetting an evicted topic must never
make its missing history appear complete. A cursor has meaning only within its
declared publisher/workspace history; it is not interchangeable with a cryptographic
ratchet generation or an application read receipt.

A retained-history request is an access operation, not a subscription or grant.
The requester must be an authenticated current member with read permission for
every selected topic under accepted policy. Denial must not disclose whether
private history exists or has been evicted. Authorized requests can distinguish
missing history from an empty selection; neither implies that newer data does not
exist. Current publisher authorization also governs the initial direct-publisher
retrieval profile; arbitrary replica-holder access requires its own verified path.


Recovery progress belongs to one publisher, cryptographic epoch and exact topic
selection. It records contiguous verified coverage within that publisher's retained
index, independently of application delivery. Progress must commit with matching
receiver security and receive evidence. Changing the publisher or selection must
not silently inherit another history; restoring older state without progress must
not invent it. A cutoff observation alone cannot advance recovery progress.

## Membership agreement

Workspace presence describes recent reachability independently of membership,
map position and application subscriptions. A first join changes membership;
returning online refreshes presence for the existing membership. A workspace
must update those group views promptly without waiting for PLI. Old reachability
expires visibly, and an unreachable member remains a member until an authorized
removal is accepted. Restoring a saved roster does not prove anyone is online.

Membership synchronization must distinguish verified current state from saved
state that has not been compared with reachable peers. A presence announcement
can prompt verification; it cannot authorize an unverified roster or resolve a
conflicting membership branch. These observations remain workspace scoped.

Equal epoch numbers do not establish that two endpoints accepted the same
membership branch. A peer's state comparison is a synchronization claim, not
authority to replace local membership, import another branch's keys, or restore
a removed member. A detected disagreement remains unresolved until an authorized
reconciliation procedure succeeds. Data exchange under locally accepted state
may continue; cross-branch exchange is not implied.
