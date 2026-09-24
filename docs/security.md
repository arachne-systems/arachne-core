# Security model and boundaries

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
epoch. ADR A2 retained snapshots have the same cost and the same bound.

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

## Network metadata and availability

Direct paths, public address lookup, local discovery, and relays can expose
network metadata to the relevant network and service operators. Depending on
the path this may include IP addresses, endpoint identifiers, connection
timing, traffic volume, and routing relationships. The core does not promise
anonymity or conceal all metadata.

Any peer, relay, discovery service, ISP, or local network can be unavailable,
misconfigured, or hostile to availability. A relay or lookup service assists
connectivity; it is not the authority for MLS membership. Core does not promise
that direct paths will work through a firewall or that every publication will
reach an offline peer.

## Local persistence

`arachne-store` encrypts values with AES-256-GCM using a derived key based on a
root key supplied by the host and a caller-selected scope. It authenticates the
record index when opening the database and authenticates record ciphertext
when each record is read. The host remains responsible for protecting the root
key, filesystem access, backups, and concurrent-open lifecycle.

The store's `FreshnessAnchor` detects rollback only when the host saves the
anchor somewhere independent of the database and verifies it during restore.
An attacker who can replace the entire database and its only freshness value
can roll both back together. Key loss also means stored state cannot be
recovered by Core.

The runtime exposes the anchor through `record_freshness` and checks it in
`restore_record_storage_with_freshness`. The check is exact equality, not
"at least this revision". Two stores for the same workspace and root share one
key, so an old file from an earlier lineage can have a higher revision and
still authenticate. A rollback that is accepted replays MLS state and reuses
sender counters, which reuses AES-GCM nonces. Exact equality has a cost:

- If the process stops after a commit but before the host saves the new
  anchor, the current database no longer matches. Restore fails closed, and
  the host must decide how to recover.
- Some `execute` operations commit and send in one call. The host cannot save
  the anchor between that commit and the send. A crash in that window,
  followed by a rollback to the saved anchor, is not detected.
- A restore without an anchor does not detect rollback.

For staged workspace, membership, publication, and recovery operations, persist
the exact candidate before adoption. If a write result is uncertain, close and
restore from the last committed state before retrying. This prevents the host
from advancing live cryptographic state after losing the matching durable
snapshot.

## Host responsibilities

An integrating application must, at minimum:

- generate, protect, rotate, back up, and restore endpoint and store secrets;
- authenticate application users/devices before binding them to workspace
  credentials;
- persist accepted and staged state using the documented commit/adopt order;
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
