# Security and group management

A workspace must let authorized people and services collaborate while rejecting outsiders and unauthorized actions by existing members. Multiple administrators and intermittent connectivity are normal operating conditions. Security enforcement belongs in each receiving endpoint, not only in the plugin UI.

This document specifies required behavior and unresolved policy choices. It does not select a cryptographic protocol or claim a completed security implementation.

The [threat model](threat-model.md) maps these requirements to concrete attacks,
existing evidence and gates for architecture changes. Crypto selection must
account for retained-key compromise, original authorship, replay and partition
authority as well as successful message delivery.

## Trust boundaries

| Boundary | Required validation |
| --- | --- |
| Invitation → admission request | Intended workspace authority, capability scope, validity and applicable replay limits |
| Address hint → connection | Expected endpoint identity independent of the returned IP or relay route |
| Endpoint credential → member authority | Verified binding to the participant and current workspace permissions |
| Management request → accepted state | Authorized actor, valid dependencies and the selected conflict/finality rules |
| Received bytes → publication | Bounded framing, cryptographic validity, original author, recipient scope, authorization context and replay/expiry rules |
| Stored state → recovered endpoint | Integrity, consistent committed security state and protocol-appropriate rollback prevention |
| ATAK local stream → fabric | Authenticated local access and explicit workspace/recipient mapping |

Relays and discovery services are not membership authorities. A ciphertext holder does not gain decryption or administration rights merely by storing records. Authorized members may be malicious or compromised: their ability to connect does not allow them to grant themselves additional rights.

## Authority model

Membership policy defines who can invite, approve admission, remove members, change topic access, promote or demote administrators and authorize device credentials. These are distinct actions even if the first UI groups some of them together.

Every management operation needs authenticated actor identity, workspace scope and the relevant state/dependency references. Receivers evaluate authority against the operation's valid policy context. A local permission table is a routing projection; installing one without verification is not a group-management protocol.

The following questions need concrete policy decisions before usable onboarding:

- Which members can issue invitations, and which invitations require approval?
- Can one administrator finalize each kind of change, or do some changes require additional approval?
- What happens when the last administrator loses access?
- How are device loss and member removal distinguished?
- Which operations can become effective during a partition, and when are they final?

No timeout or absent response may be interpreted as human approval unless an explicit authorized policy makes that behavior valid. Protocol coordination roles, such as a committer or steward, do not automatically carry administrator rights.

### Receiver checks for concrete management actions

The current portable verifier accepts one `Promote`, `Demote` or `Remove` intent
identified by stable member ID, checked against a public MLS commit and the
receiver's private accepted MLS state. The actor must be a current administrator.
The exact role delta and removal target must match; other proposals, extra role
changes, identity replacement and unrelated group-policy changes are rejected.
Removing an administrator includes its role removal in the same commit. The
last administrator cannot be demoted or removed by this profile; self-removal
belongs to a separate leave workflow. These bounds do not define lost-device
recovery, a quorum or global partition finality.

A public checkpoint verifier cannot check a group's membership MAC. Existing
members must also process the commit using their private MLS state. Verification
uses a disposable state copy and does not adopt or save the proposed transition.
The executed guard tests *(receipt retained in Git history)*
exercise valid operations, malicious member commits, altered membership tags,
exact action scope, old invitation rejection after admin removal and signed-object
key separation. Test-only merge code advances scenarios after the guard succeeds;
runtime management integration and ATAK member controls remain to implement.
The portable staged API now retains typed public history through protected
save/restore, including old invitations that cross role changes. It leaves the
original owner unchanged and still requires host save/readback before adoption.
A removed recipient receives a protected removal record rather than an active
Workspace. Its record retains local identity and verified removal metadata without
group keys. The host must replace the active snapshot atomically before adopting
removal. Runtime reopen retires the endpoint and returns a removed status; it does
not configure data delivery. Management notification, live save/adopt and ATAK
controls still require integration. This does not prevent deliberate restoration
of a different old backup or revoke uninformed disconnected peers instantly. A rejected competing branch is not a completed
reconciliation policy.

## Invitations with approval in advance

The normal admin-issued invitation carries authorization in advance. Its issuer
does not need to be online when the joiner redeems it. An available member can
verify the invitation and coordinate the authorized cryptographic admission
without acquiring a general right to invite or approve other people. The joiner
must prove possession of its workspace-specific credentials; presenting an IP,
ATAK callsign or copied membership record is insufficient.

The invitation binds the intended workspace, issuing authority, granted role and
permissions, validity constraints, and the applicable authorization context. It
must not contain a permanent shared traffic key. Initial implementations must
not claim that validating the signature alone establishes accepted membership:
protocol processing must also enforce the grant and produce usable protected
state for the joiner and existing members.

A request-approval link is a separate explicit mode. It starts a request that
requires a later authorized decision. Do not silently turn an already authorized
invitation into a request requiring its issuer to return. If no member or other
authorized admission participant is reachable, admission waits for connectivity;
admin presence is not itself a prerequisite.

Expiry, revocation and redemption limits require concrete partition rules.
Disconnected peers cannot know a revocation they have not received. A bearer
invitation can be copied; a globally single-use promise requires coordinated
redemption or a narrower construction such as a grant bound to one recipient's
credentials. The link UI must describe only guarantees the implementation can
enforce. Exact bearer-invite reuse limits and conflict rules remain under
engineering evaluation; they must not be solved by requiring the issuer online.

The user experience target is Signal-style group management: create a workspace,
share its link or QR code, join under its configured approval mode, manage members
and admins, and leave. Normal users do not select epoch, quorum or committer
settings. Signal documents group links/QR codes with optional admin approval:
https://support.signal.org/hc/en-us/articles/360051086971-Group-Link-or-QR-code .
This is the interaction reference, not a selection of Signal's backend protocol.

## Cryptographic groups and MLS

MLS provides group key establishment and protected membership transitions. Applications still define authorization policy, credentials and delivery/coordination behavior. Its architecture permits peer-to-peer delivery and application access rules; it does not require one human administrator or a central TAK Server. See [MLS architecture, membership](https://www.rfc-editor.org/rfc/rfc9750.html#section-6.1) and [MLS protocol](https://www.rfc-editor.org/rfc/rfc9420.html).

A workspace may require more than one cryptographic audience. Topics with the same authorized readers can share a context. Private directed chat needs recipient confidentiality beyond workspace-wide encryption. Likewise, giving a service a symmetric group decryption key cannot provide cryptographic write-only access merely by denying subscriptions.

The library boundary should expose valid actions, verified transitions, protected publications and required durable state without exporting a vendor's internal MLS objects. It must accommodate more than a single integer epoch if the chosen protocol requires branch or sender-specific context. Authorization policy revision and cryptographic epoch are distinct concepts.

The crypto/coordination implementation remains to be selected. Candidate research and pinned source evidence are available in [offline-group research](../wayfinder/decentralized-atak/research/offline-groups.md); current executable results are in [STATUS.md](../STATUS.md).

### Asynchronous MLS admission mechanisms

Standard MLS already supports asynchronous membership changes. RFC9750 section6.3
states that operations do not require two clients to be online simultaneously;
the surrounding system must supply asynchronous reliable delivery. Thus a live
member is a requirement of a particular peer-assisted implementation, not a
fundamental MLS requirement. An available retained source of the necessary state
can support other admission paths.

Two standard mechanisms are relevant. A member can commit an Add for the joiner's
KeyPackage and deliver a Welcome asynchronously. Alternatively, a joiner can
construct an external Commit using appropriate current-epoch GroupInfo with
external_pub and the public ratchet tree. External joins remain subject to the
application's authorization policy; GroupInfo is epoch-specific and cannot serve
as a indefinitely reusable current-state snapshot inside a static invite link.

The application must bind the invitation grant to allowed admission and validate
it consistently at receiving peers. A preissued invitation is not automatically
an MLS Welcome, and MLS does not itself define administrator roles or invite-link
reuse/revocation rules. Sources: RFC9750 sections6.1,6.3,6.4
(https://www.rfc-editor.org/rfc/rfc9750.html#section-6.3) and RFC9420 section12.4.3.2
(https://www.rfc-editor.org/rfc/rfc9420.html#section-12.4.3.2).

## Partition semantics

A network partition creates different knowledge at different endpoints. The product must distinguish ordinary data availability from membership-change finality.

Existing admitted peers should continue permitted exchange wherever usable paths and key state exist, without requiring a particular administrator online. Approval-required joins still need an authorized approval. Whether a membership change can finalize inside an isolated cluster is an unresolved product/protocol decision.

Two possible policy families have different consequences:

| Policy family | User-visible consequence | Required evidence |
| --- | --- | --- |
| Coordination before finality | Some management changes wait until the necessary participants reconnect | The required coordination is explicit, recovers after failures and does not depend permanently on the creator |
| Changes effective within partitions | Separate clusters may temporarily act on different accepted authority | Causal validity, conflicting revocations and key disclosure consequences are defined; merge does not silently resurrect authority |

Neither family is selected here. A wall-clock timestamp alone is not a sufficient authority conflict rule. Reconciliation cannot undo plaintext disclosed while an isolated endpoint was acting on earlier knowledge.

## Revocation and rejoin

A revocation changes which credentials may act and which endpoints receive future protected state. Receivers that know the accepted revocation reject operations that no longer have authority. Removing a subscription alone is insufficient because a malicious endpoint can bypass its local subscription UI.

Disconnected uninformed endpoints cannot enforce a change they have not learned. Already learned plaintext cannot be erased remotely. Re-admission requires a fresh authorized action with defined treatment of the prior removal; replaying old credentials or invitations must not silently restore access.

An endpoint returning after a long absence must recover supported key/control dependencies or receive a clear rejoin-required outcome. Rejoin policy must define history access rather than handing out all historical keys to make synchronization convenient.

## Durable security state

Identity credentials, accepted policy, cryptographic state and pending transitions must have a recoverable commit boundary. A successful UI operation cannot depend solely on volatile memory when a crash would lose its security meaning.

The selected implementation must define:

- Which state must be persisted before a transition is emitted or acknowledged.
- How pending actions are retried without unauthorized duplicate effects.
- How restart avoids reusing cryptographic sender state or rolling authority backward.
- How old key material is deleted within the supported offline-recovery policy.
- What recovery is possible after loss of device storage or keys.

Workspace security-state storage and recovery mechanisms remain open. Development SDK signing credentials are build artifacts, not workspace credentials.

### Endpoint credential storage

The Android adapter generates a random 32-byte transport credential per explicit
local credential slot and wraps
it with an AES-256-GCM key in Android Keystore. The wrapping key is non-exportable
through the Keystore API; the unwrapped transport credential must enter the
application and Rust process memory to operate Iroh. Hardware-backed protection
is device-dependent and has not been established by emulator checks. See the
[Android Keystore contract](https://developer.android.com/privacy-and-security/keystore).

The record lives in the running host's private `noBackupFilesDir`, under
`data-fabric/<slot>.bin`; `endpoint-v1` is the current development-fixture slot.
In ATAK this belongs to ATAK's UID, not the separately
installed plugin package. Other code running with that UID is inside the trust
boundary. A lifetime file lock prevents a second local owner from starting with
the same saved credential. The file contains a version byte, 12-byte random GCM
IV and 48-byte authenticated ciphertext; it contains no plaintext credential.

Creation uses `AtomicFile` and validates the committed record before starting
the endpoint. Recovery bounds the record to 61 bytes, checks its version and
authenticates its ciphertext. Missing half of the record/key pair, corruption or
decryption failure stops startup without resetting identity. If both are absent,
the installation creates a new endpoint identity. Device loss, data clearing and
intentional identity reset will require explicit member/device recovery rules;
there is no reset UI yet. See [AtomicFile](https://developer.android.com/reference/android/util/AtomicFile)
and [non-backup storage](https://developer.android.com/reference/android/content/Context#getNoBackupFilesDir()).

The portable node accepts a caller-supplied credential without depending on
Android storage. Restoring this credential does not restore memberships,
permissions, subscriptions, MLS state or message history. Static credential
recovery provides no monotonic policy/epoch rollback protection. Whole-device
cloning, hardware power-loss durability and compromised-host resistance are not
proven by process restart or ciphertext tampering checks.

### Privacy between workspaces

Real workspaces must use distinct credential slots, transport endpoint keys and
membership credentials. A stable key is stable within its workspace; it is not a
global device identity published to every group. Onboarding must not introduce
a common public joiner identity or disclose the joiner's other memberships.
Peer lists, invitations and control responses must remain workspace-scoped.

Separate group encryption alone does not meet this requirement if transport keys
or application identifiers still match. ATAK's adapter must map host-global UIDs
and their references into workspace-specific identifiers before publication.
Callsign presentation needs workspace-specific control. Arbitrary payloads may
contain identifying information that the generic fabric cannot interpret or
remove safely.

Separate endpoint keys do not conceal IP addresses, timing or repeated content.
LAN discovery that advertises all local endpoint keys at the same address can
also correlate them; it must not be automatically enabled as a privacy-preserving
discovery mechanism. Stronger network anonymity is not an established capability.

The current development adapter is not privacy-complete: it has one fixture
endpoint and preserves native ATAK UIDs. Do not attach multiple real workspaces to
that endpoint and claim their memberships are unlinkable. Admission integration
must assemble separate identities and prove the adapter mapping independently.

## Required security scenarios

The runnable acceptance contract must cover these behaviors with real validation paths, including protocol injection that bypasses UI controls:

| Scenario | Required result |
| --- | --- |
| Creator/admin offline | Another authorized administrator can manage within the declared coordination policy |
| All admins offline | Existing authorized data exchange continues; approval-required requests remain pending |
| Concurrent admissions | Each operation has an explicit outcome and usable group state converges under the supported schedule |
| Partition and merge | Effective versus final changes are distinguishable; reconciliation follows declared authority rules |
| Revocation racing with re-admission | Stale state does not silently restore removed rights |
| Admin demotion and mutual demotion | Actor validity and recovery outcomes follow explicit policy |
| Invite replay | Enforced use/expiry guarantees match what the invitation UI promises |
| Unauthorized feed/member management | Receivers reject the action even when sent directly over the protocol |
| Crash during transition | Restart preserves the commit boundary and cannot roll back security state |
| Long-offline member | Supported recovery succeeds or rejoin is explicit |

The detailed scenario inputs are in [group-scenarios.json](../wayfinder/decentralized-atak/research/group-scenarios.json). A scenario specification is not execution evidence; test outcomes belong in the repository's evidence records.

## Current protected workspace storage boundary

The portable security owner seals bounded state with AES-256-GCM under a
domain-separated HKDF key derived from the host-protected root. Workspace and
endpoint identities authenticate the snapshot context. Android stores only the
ciphertext with atomic file replacement under noBackupFilesDir; plaintext MLS
state does not cross JNI. The current bound is128KiB plaintext/256 provider records.
Larger state is rejected; this is not a thousand-member storage claim.

The version3 workspace snapshot includes bounded locally prepared admissions:
request digest, authenticated endpoint, issuer, resulting epoch and exact
commit/Welcome/authorization response. Saving this candidate preserves group
state and retry material as one authenticated record. Retry lookup checks the
exact request, transport-authenticated endpoint and current issuer/member
eligibility. Records are not a complete branch history and are not silently evicted;
at most16 local admissions share the128KiB total bound. Versions1/2 remain readable.

The native session stages one candidate, blocks other operations until adoption,
and exposes no response while staged. The Kotlin store saves/readbacks its sealed
candidate before adopting it; on failure the coordinator must close and restore
disk state before continuing. This boundary is connected to authenticated Iroh control requests: the native
receiver derives the requester from TLS, stages verified admission, and releases
the retained reply only after local adoption. Android instrumentation exercises
this with two endpoints inside each emulator; cross-emulator onboarding and UI
coordination remain unverified. Remote-history
retrieval/synchronization and outbox remain unfinished. Joiner staging now verifies
all supplied Add steps against its saved invitation checkpoint, validates Welcome,
and seals the resulting owner with its proof history. Android saves/readbacks and
adopts that candidate before deleting pending state. The user catalog handoff and
startup resolution when both records remain are not yet wired into the plugin UI. Rollback to an older valid snapshot is
not detected. Core snapshot restoration is distinct from actual host crash
recovery during admission, which has not been tested.
The application must not emit a membership transition or acknowledge durable
acceptance until the corresponding state and pending output commit together.
The selected small-slice representation is one encrypted snapshot; the isolated
SQLite gate demonstrates a different persistence option, not a second active
store that the plugin must coordinate.

## Joining the intended workspace

A valid MLS Welcome proves cryptographic consistency of the offered group; it
is not sufficient to identify the intended workspace or authorize its history.
A malicious member can offer another internally consistent branch. Matching the
workspace ID, epoch, name or administrator list is insufficient.

The candidate join path pins the SHA-256 digest of an administrator-issued,
signed MLS GroupInfo checkpoint in the trusted invitation. Fetching the
checkpoint from a peer does not make that peer a new trust root. The prospective
member validates the exact digest, MLS signature/tree, workspace ID, credential
bindings and authority roster, then verifies each subsequent membership commit
and its application authorization. The MLS-validated Welcome must match the
resulting group context, confirmation tag and ratchet tree before the host may
install the joined workspace. Shared names and profiles must then be authenticated
under that workspace's policy.

The reusable security crate currently implements checkpoint export and public
Add-proof replay, including ordinary-helper fulfillment of a preissued grant.
The pending-join owner now protects and restores its identity and KeyPackage;
it validates Welcome against the original checkpoint branch before returning a
provisional joined owner. The signed invitation codec and provisional helper admission are implemented
in the core. Invitation/checkpoint transport, durable history transfer, host
pending-to-joined commit/recovery and UI remain integration work. Its
current replay path rejects management operations other than a single Add;
admin-role changes, removals, expiry/revocation and competing-branch recovery
remain unsupported here. This is not a partition-finality policy.

New local groups emit public MLS handshakes for replay and include the ratchet
tree in Welcome messages. Application messages remain MLS PrivateMessage
ciphertext. Checkpoints and handshakes reveal roster metadata to their holders:
they must travel only through authorized encrypted channels, never public
lookup advertisements or unprotected gossip. Authenticated Iroh admission control
now carries the retained Add/proof and Welcome to the endpoint authorized by the
request. General history retrieval and checkpoint distribution are still unfinished. Existing saved groups retain their prior handshake configuration;
joining those groups requires an explicit supported transition.

## Comparing accepted membership state

The current runtime compares a workspace-scoped fingerprint of the MLS epoch
authenticator when an admitted peer claims the same epoch is current. The
fingerprint is SHA-256 over a versioned domain label, workspace ID, epoch and
epoch authenticator. It is returned only to locally admitted peers; terminal
removal replies do not expose subsequent epoch fingerprints. This uses the
epoch-comparison purpose described in [RFC 9420 section 8.7](https://www.rfc-editor.org/rfc/rfc9420.html#section-8.7),
with OpenMLS 0.8.1's public `epoch_authenticator()` API. It does not expose the
epoch secret, encryption keys or resumption PSK.

Different fingerprints yield `membership_branch_mismatch`; absent/malformed
fingerprints yield `membership_unverified`, including older peers without this
field. Neither result adopts remote state or chooses a winner. The plugin shows
a warning alongside normal workspace status. The warning is observed session
state, not a durable conflict-resolution record; reopening must query again.
A malicious admitted peer can lie about its fingerprint, so equality is not
global finality or independent verification of that peer's internal state.

This comparison currently detects same-epoch disagreement. Different-length
branches still require explicit ancestry/conflict handling. A recovery policy
for concurrent changes, demotions and removal races remains required; detection
alone does not satisfy [RFC 9420 section 14](https://www.rfc-editor.org/rfc/rfc9420.html#section-14)
or the project's partition scenarios.

A valid membership query from a current peer also informs the local controller
which peer initiated contact. This allows reopened workspace owners to check
agreement without requiring a second manual reconnect. Denied and former-member
queries do not nominate a peer. Checks retain the existing five-second cadence;
this is opportunistic peer selection, not exhaustive all-member verification or
a scalable dissemination policy. The isolated Android controller evidence is
the persisted branch warning check *(receipt retained in Git history)*.
