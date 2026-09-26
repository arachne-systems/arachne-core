# Security model and boundaries

## BLUF

Membership authority comes from verified MLS state. Concurrent membership
changes use a deterministic branch choice. A node saves the winning candidate
before it adopts it. It blocks new protected sends while a required removal
waits, and keeps receiving. Recovery depends on a bounded set of sealed
snapshots. A node that loses below that set needs administrator re-add.

Arachne Core is pre-release software. Its tests demonstrate selected behaviors;
they are not a formal protocol verification, independent security audit,
certification, or authorization to use in a particular environment. Do not use
this page as a substitute for an application threat model and deployment review.

## What the layers provide

| Layer | Intended protection | Does not establish |
| --- | --- | --- |
| MLS workspace state (`arachne-security`) | Cryptographic workspace membership and protected group application messages, subject to correct key/state handling. | A person's legal identity, device integrity, or the security of the host application. |
| Iroh endpoint and QUIC transport (`arachne-node`) | Authenticated endpoint connections and transport confidentiality/integrity for a path. | Workspace membership, topic authorization, anonymity, or delivery availability. |
| Routing policy (`arachne-routing`) | Decides which endpoint/topic operations are permitted or requested by the current local policy. | Independent cryptographic confidentiality for each topic. |
| Encrypted record store (`arachne-store`) | Authenticated encryption of local record contents and integrity checking of the accepted record set. | Protection when the host's root key is exposed or detection of whole-database rollback without an external anchor. |

These layers are complementary. A valid endpoint connection is not sufficient
to join a workspace. A workspace member's endpoint association and an installed
routing policy must also be valid for the intended operation.

## Identity and membership

Endpoint keys are network identifiers, not verified names. MLS membership
proves possession of workspace credentials under the protocol; it does not
prove that a member is the person or organization shown by an application
display name. The host must bind its account/device enrollment rules to the
workspace credential it accepts.

Membership changes become effective through workspace state transitions. A
disconnected peer cannot learn about a removal until it receives the relevant
updated state. Previously delivered plaintext cannot be recalled from a member
or application that already received it. Applications should communicate these
limits and define how they treat stale or offline members.

## Routing is not a cryptographic boundary

Topics and permissions guide distribution and application handling. They do not
create per-topic MLS key schedules. If members of one MLS workspace must not be
able to decrypt one another's data, they must not share one cryptographic
workspace merely because their subscriptions or routing policies differ.

### Receive window for recent epochs (forward-secrecy trade-off)

Peers in a disconnected network are often at different epochs. To let them
exchange data after a partition heals, each member keeps the object base
secret of the last `RECEIVE_EPOCHS` = 4 epochs, for **receive only**:

- Objects are always **sent** with the current epoch. An old secret is never
  used to encrypt.
- An object from epoch `E` decrypts while `E >= local epoch - 4`. After that
  the base is deleted and the object fails with `object epoch expired`.
- An object from a future epoch fails with `object epoch ahead`. The runtime
  keeps it out of the inbox; it is recovered again after this node catches up.
- The author must be in the **current** roster, at the same leaf, with the
  same signature key. A removed member cannot inject objects into an old
  epoch, also not objects that it made before its removal. Such objects that
  were in flight at removal are lost.
- A new member never has bases for epochs before its join, so it cannot
  decrypt earlier objects.

**Cost.** The retained bases are secret and are stored in the workspace
state, sealed at rest. Someone who takes the device state can decrypt captured
objects from up to 4 past epochs, not only from the current epoch. A removed
member who still has an old epoch base can read objects that others sent in
that epoch, but not objects sent after its removal, because those use the new
epoch. The separate A2 rollback snapshots retain more secret state and can
cover more epochs. Their limits are below; they do not use the four-epoch
receive bound.

### Application namespaces (domain separation, not isolation)

Each protected object is bound to an **application namespace**. The runtime
uses the first topic segment: `chat` for `chat/room/1`, `atak` for
`atak/cot`. The namespace is used in two places:

- **Key.** The object key is
  `HKDF-Expand(MLS-Exporter("arachne/object-base/v2", "", 32), "arachne/object-namespace/v2\0" || len || namespace)`.
  Each namespace gets its own key in each epoch.
- **Authenticated data.** The length-prefixed namespace is in the SFrame AAD
  and in the signed bytes, together with the full publication context (topic,
  id, sequence, recipients).

What this gives:

- An object made for one application is never accepted as another
  application's object. The key, the AAD and the signature all fail.
- A bug in one application (for example nonce or AAD misuse) stays in that
  application's key domain.

What this does **not** give:

- **Confidentiality between applications.** Every member of the workspace can
  compute every namespace key from the shared MLS exporter. An application
  that runs on a member device, or a member who is not allowed to see an
  application's topics, can still decrypt that application's objects if it
  gets the ciphertext. Routing policy only limits distribution.
- **Protection from a member.** A member can make valid objects in any
  namespace under its own identity.

If data must stay confidential from some members or from some applications,
use a separate workspace (a separate MLS group) for each sensitivity level.

The basic `publish`/`poll` API is a transport/pub-sub path, not protected MLS
group messaging. For an admitted workspace, use the staged protected path and
commit/adopt the candidate in the required order. See
[Integration](integration.md#publication-paths).

## Concurrent membership changes and recovery

### Branch choice and authority

At the first epoch where two accepted histories differ, Core compares the
verified commit class, then SHA-256 of the exact commit bytes. The lower pair
wins. The classes are, in order: Remove or Leave; Demote or DisableInvitation;
other administrator changes; admission; member self-update. A longer history
does not gain priority. Reports and branch rows are search hints until the
receiver verifies the corresponding step and computes its key locally.

The receiver opens its sealed snapshot at that parent epoch and checks its
epoch and common history. It replays the winning step, saves the complete
candidate, reads it back, and then adopts it. Receipt alone does not change
accepted membership. An authenticated endpoint or gossip relay cannot grant
membership or change a commit's class.

An administrator can authorize admission and management changes. A member
can update its own leaf and sign its own Leave. A signed revocation order can
be carried by another member. Its proof must establish the issuer's authority
at the anchor and bind the winning proof path to the receiver's exact group
context. Demotion after the anchor does not cancel a valid earlier order.
An order is single use and expires after 64 chain epochs. Local wall clocks do
not decide that expiry.

### Removal and send quarantine

When a losing history contains a valid removal, the receiver carries that
order onto the winning history. While a carried Remove or Leave waits, it
blocks all new protected publications, including publication chunks from an
already-open producer. Membership reception and data reception remain
available. The guard also blocks automatic self-updates and local data
re-publication. The activity view reports `recovering` with reason
`branch_send_quarantined`. The accepted membership state stays intact until
the carried step is saved and adopted.

After removal, new protected data uses the accepted winning epoch. A removed
member cannot decrypt it with retained old state. That does not erase old
plaintext or stop disconnected peers from sending on a branch before they
learn of the removal. Recovery needs peers to exchange the relevant verified
steps. A lost or unavailable peer is not evidence that its branch has settled.

### Snapshot retention and settlement

The snapshot set holds at most 64 epochs and at most 16 MiB of sealed secret
state in total. One snapshot can use that full byte budget. The effective
window is whichever limit is reached first. At 2,049 members, the measured
snapshot was 3,208,876 bytes: about five such snapshots fit. The native-store
capacity test retained one such snapshot in seven physical records and
restored after member 2,050 joined. This is not a 64-epoch guarantee at large
rosters. See [H1 evidence](evidence/h1-night-2026-09-26.md).

Epoch E settles only after every member in E's roster reports E+1 or later
on the accepted chain. Core accepts signed heads and authenticated replies,
and checks the reported fingerprint against that chain. A removed member
cannot report the next state, so removal epochs can remain until a retention
limit applies. Snapshot deletion uses a saved candidate. Restart can delay
settlement because observations are volatile; it cannot create an observation.

Rollback snapshots contain MLS secrets. Capture of these snapshots can expose
traffic from their epochs, in addition to the ordinary receive window. Core
deletes a snapshot when it settles or leaves the count or byte window. If one
snapshot exceeds the byte budget, Core expires that recovery position instead
of refusing a valid membership change. Other sealing or storage errors fail
the change.

If the winning fork is older than the available snapshot, the losing node
becomes orphaned. Its activity view reports `recovering` with reason
`branch_orphaned`. It retains local data but cannot publish or create new
membership changes. An administrator must explicitly admit a fresh member
state. Old state cannot perform an external commit to admit itself: a removed
member could use the same route.

### Retained data and local actions

Core can re-encrypt retained, locally authored objects on the winning branch.
It keeps the stable object ID, checks the current direct audience, and uses
the installed routing revision. An empty direct audience or an expired current
value is discarded. The encrypted recovery queue holds at most 4,096 objects
and 512 KiB. When that queue is full, it drops the oldest retained data and
reports `republication_lost`. This queue is not an application archive.

Pending received plaintext remains available. Its `from_losing_branch` flag
and author epoch identify a discarded branch. Core does not re-publish another
member's plaintext. Objects already acknowledged to the host are outside this
inbox update; the host controls their storage and display.

Core retries a valid, locally issued non-revocation action once. It reports
`action_lost` if the action is invalid on the winner, loses again, or issued an
invitation link tied to the discarded checkpoint. The host must issue a new
link in that last case. Retry state and recovery queues are in the same native
transaction as the branch. Outcomes are drive-call results, not a separate
acknowledged event inbox.

### Current transport bounds

Binary membership steps use at most 117 KiB inside a 128 KiB control reply.
Admission batches can contain 128 members. Paged join history has both a
4,096-step cap and a 16 MiB total byte cap; a maximum-size checkpoint plus
64 maximum-size steps fits that byte cap. Larger steps do not bypass the
per-step limit.

A carried revocation proof must currently fit one runtime step. A large
roster checkpoint or a long anchor proof can exceed it even when the security
codec can verify the proof. The runtime then refuses the change. A separate
paged proof transport is still required for those cases. The large native
store test proves storage capacity; it does not prove large-roster fork
recovery over the network.

## Network metadata and availability

Direct paths, public address lookup, local discovery, and relays can expose
network metadata to the relevant network and service operators. Depending on
the path this may include IP addresses, endpoint identifiers, connection
timing, traffic volume, and routing relationships. The core does not promise
anonymity or conceal all metadata.

The gossip overlay is named by a tag that a gossip link sends inside its
encrypted channel. The tag is a hash of the workspace ID and a gossip key. The
workspace creator makes the gossip key (32 random bytes) one time. Each Add
sends the key to its joiners only inside the encrypted GroupInfo of the
Welcome. The key is not in the group context, because MLS handshakes and join
checkpoints are public. The key does not change when the epoch changes, so
members at different epochs find the same overlay. A member that is removed
keeps the key and can still calculate the tag. The tag only stops a party that
knows the workspace ID, but does not have the key, from connecting the tag to
the workspace. The tag is not access control: the node accepts a gossip link
and data-plane traffic only from endpoints in the installed policy. A state
that has no gossip key cannot join an overlay. There is no fallback.

Operators can replace n0's relays with their own relays, and can stop n0's
public address lookup (`TransportOptions` in `ClientConfig`).

Any peer, relay, discovery service, ISP, or local network can be unavailable,
misconfigured, or hostile to availability. A relay or lookup service assists
connectivity; it is not the authority for MLS membership. Core does not promise
that direct paths will work through a firewall or that every publication will
reach an offline peer.

## Local persistence

Native record storage is the only persistence mode. Core saves each staged
candidate, reads it back, and only then adopts it; the host never handles
state bytes. `arachne-store` encrypts values with AES-256-GCM using a derived
key based on a storage root key supplied by the host and the workspace scope.
The storage root is not derived from the endpoint secret; rotating the
endpoint identity does not change the storage key. It authenticates the
record index when opening the database and authenticates record ciphertext
when each record is read. The host remains responsible for protecting the root
key, filesystem access, backups, and concurrent-open lifecycle.

A stored value longer than 512 KiB is saved as parts, each its own store
record, so no record passes the 1 MiB record limit. The MLS provider keeps the
ratchet tree as JSON: about 1,270 bytes per member, about 3.7 MB at the roster
the invitation checkpoint bound allows (about 2,900 members).

Stored data is versioned. A store file carries its format (format 1) in the
SQLite header and in the authenticated head, and the runtime records carry
their own format record (format 1). There are no legacy readers: an unknown,
older-than-first or newer format fails with `FormatNotSupported` (code 303)
before any state is used. A later format change adds a migration step that
runs on restore and saves the upgraded records in one commit. A new store is
built in a temporary file and linked into place only when complete, so a crash
during creation never leaves an empty file that cannot open.

The store's `FreshnessAnchor` detects rollback only when the host saves the
anchor somewhere independent of the database and verifies it during restore.
An attacker who can replace the entire database and its only freshness value
can roll both back together. Key loss also means stored state cannot be
recovered by Core.

Where the platform supplies monotonic storage (a hardware-backed keystore,
a counter, or storage an attacker who replaces the database files cannot roll
back), the host passes it as an `AnchorStore` with
`StorageConfig::with_anchors`. Core then keeps the anchor itself and restore
requires it (B9):

- Before each commit, core saves two slots: `current` (the last confirmed
  anchor) and `next` (the anchor the commit will produce). After the commit
  and its read-back, it saves `next` as the new `current`.
- Restore accepts the store only if it matches `current` or `next`. A
  rolled-back database matches neither and is refused with `CandidateStale`.
  A crash between a commit and its confirmation matches `next`, so it
  restores, and core confirms that anchor.
- A missing anchor fails closed. If the anchor save fails, the session stops
  (uncertain outcome) until it is closed and restored.

Without monotonic storage the anchor stays optional. The runtime exposes it
through `record_freshness`, and `restore_workspace` checks it when the host
passes the saved anchor. The check is exact equality, not
"at least this revision". Two stores for the same workspace and root share one
key, so an old file from an earlier lineage can have a higher revision and
still authenticate. A rollback that is accepted replays MLS state and reuses
sender counters, which reuses AES-GCM nonces. Exact equality has a cost:

- If the process stops after a commit but before the host saves the new
  anchor, the current database no longer matches. Restore fails closed, and
  the host must decide how to recover.
- Adopt operations commit and send in one call. The host cannot save the
  anchor between that commit and the send. A crash in that window, followed
  by a rollback to the saved anchor, is not detected.
- A restore without an anchor does not detect rollback.

For staged workspace, membership, publication, and recovery operations, core
saves and reads back the exact candidate before adoption. If a save fails or
does not read back, the session refuses further operations until it is closed
and restored from the last committed state. This prevents live cryptographic
state from advancing past the durable state. A candidate that is already in
storage cannot be discarded.

## Host responsibilities

An integrating application must, at minimum:

- generate, protect, rotate, back up, and restore endpoint and store secrets;
- authenticate application users/devices before binding them to workspace
  credentials;
- attach record storage to every session that holds a workspace, and keep the
  storage directory private;
- derive routing policy from current accepted membership state;
- avoid logging invitation material, secrets, plaintext, or sensitive endpoint
  metadata;
- decide how to handle offline members, stale presence, replay/retry, and
  application-level acknowledgements;
- assess the complete application and deployment, not just this library.

## Not claimed

This repository does not claim a completed independent security audit, formal
verification, certified cryptographic implementation, anonymous networking,
central identity or authorization service, automatic secure key storage,
whole-database rollback protection without a separate anchor, perfect forward
delivery to offline peers, or security based on obscurity of the source code.
