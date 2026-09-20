# Portable workspace security

`Workspace::create` owns an OpenMLS provider, signing credential and group behind
an API containing endpoint public-key bytes, a chosen member display name and
public workspace/member metadata.
The crate has no Iroh, Android, CoT or mission-data dependency. Group IDs and
signing keys are generated independently; initial authority is the creator key.
It uses the same pinned OpenMLS family and candidate authority extension as the
admission experiment. New member credentials use a version2 member/endpoint
binding; the experiment still uses version1 endpoint-only credentials. The runtime admission path enforces this binding. These formats are not a finalized protocol.

The real Android session owns this object and calls it through its existing
worker/JNI request path. Creation stays in memory until the host saves a protected snapshot. Creation alone grants no transport routing permission. The plugin integrates
verified admission and user-facing persistence; encrypted publication is the
next runtime integration step. See ../../STATUS.md for current evidence.

Run `cargo +1.98.0 test --locked --offline -p arachne-security`. Android evidence
is retained separately under evidence/workspace-native-android-2026-09-08.json;
it exercises the JNI path in plugin-package instrumentation processes, not ATAK.

## Native record persistence

`export_records()` returns `SecurityRecords`, a complete native storage image
whose values are zeroizing byte buffers. **These values contain secrets.** Only
a trusted encrypted persistence adapter may consume them; they must not enter
JSON/JNI replies, transport messages or logs. `restore_records(endpoint,
workspace, records)` requires authenticated local records and the independently
expected scope. It checks record completeness, the active MLS owner/credential,
counter state and the retained public branch before returning an owner.

The `DFWR` v1 metadata binds workspace32, endpoint32, epoch u64, optional member
profile, provider/admission counts u64 and optional history count u64. Provider
values use `security/provider/` plus their native key; admission replies use
`security/admission/` plus request digest32. Retained history has a checkpoint
and individually numbered `security/history/step/` records. Step values carry
an exact action tag, authorization and length-prefixed commit. Metadata lives
at `security/meta`. Integers are big-endian. Unknown/missing record sets fail.

The adapter diffs this image against accepted records, then commits changed
values, deletions and associated delivery state together before adopting or
emitting. The crate selects no database implementation. The real composition
test uses `arachne-store` and readback; it migrates an existing encrypted owner,
admits 100 members and reopens the administrator and a long-lived follower at
17, 65 and 100 members. It also checks an old invitation's 99-step public branch.
Command: `cargo test -p arachne-runtime --test record_storage -- --nocapture`.
This is security/storage evidence, not 100 live network endpoints.

Current transitions use the accepted roster and append control records without
the inline history counter. In-memory provider copies no longer serialize
through a file-size limit. Legacy snapshot export still enforces its format's
bounds and fails rather than dropping records. Native runtime/JNI migration and
paged checkpoint/history/Welcome transfer remain open. Existing creator files
may retain older control commits only inside admission replies; migration must
preserve those commits independently before reply retirement is enabled.

## Protected snapshots (legacy compatibility)

`seal(StorageKey)` emits ciphertext only. `restore` requires the expected
workspace and endpoint identities and reconstructs the provider/group/signer
before returning a usable owner. StorageKey is HKDF-SHA256 derived from the
host-protected root under a distinct storage domain. AES-256-GCM uses a fresh
random nonce and authenticates format, workspace and endpoint context.

The envelope is `DFWS`, version, workspace32, nonce12, ciphertext/tag.
Version2 encrypted plaintext contains epoch u64, member ID32, UTF-8 name length
u32 and name bytes, then provider record count u32 and length-prefixed key/value
pairs. Member names are trimmed, bounded to80 Unicode scalars/256 UTF-8 bytes,
and reject controls and explicit bidi controls. The chosen name is local
presentation, not a verified real-world identity. Member ID is independently
random and bound with the endpoint ID in the MLS BasicCredential; restore checks
that binding. Names may duplicate without merging identities.

Version3 adds a bounded local-admission journal between the profile and provider
records: count u32, then each request SHA256, endpoint32, issuer32, resulting
epoch u64, invitation public key32, grant signature64, redemption signature64,
and length-prefixed commit/Welcome bytes. The complete journal and provider state
share one authenticated snapshot; versions1/2 remain unchanged when no journal
is present. Restore rejects duplicate request hashes and non-increasing or future
admission epochs. Records are local transitions, not a complete branch history.

Version4 retains the joiner's verified history: profile, history length u32 and
history bytes, local-admission count/records (which may be empty), then provider
records. The history is `DFJH` version1, pinned checkpoint digest32, checkpoint
length u32 and bytes, followed by ordered Add records (invitation key32, grant
signature64, redemption signature64, commit length u32 and bytes). Integer lengths
are big-endian. The encoded history is bounded to64KiB, and the entire snapshot
still must fit128KiB. Restore replays signatures/authorization from its protected
checkpoint and compares the resulting group context, tree and confirmation tag
with restored MLS state. Locally prepared subsequent Adds extend this history.
Older snapshots without history do not invent missing remote records.

JoinProof's public replay does not verify the secret-key membership MAC. OpenMLS
0.8.1 PublicGroup passes no message secrets to framing validation; it checks tag
presence while secret-key validation occurs in member processing. Thus changing
the final membership-MAC byte is not a valid negative test for this public verifier.
Administrator signatures, signed MLS content and authorized branch matching are
checked; Welcome secret validation remains mandatory. History is private workspace
metadata and must use authorized encrypted transport, not public discovery.

Existing version1 state has no profile fields. Restore preserves its original
credential and returns no member profile; resealing preserves version1. There is
no automatic identity migration or replacement. A legacy workspace must gain an
explicit authenticated profile/credential upgrade before joining is exposed.
Names are encrypted at rest, but remote profile distribution, profile updates,
renames, local aliases and native contact mapping are not implemented.

The snapshot is limited to256 provider records and128KiB total plaintext before encryption;
this keeps the JSON JNI envelope below its128KiB request limit. Larger state
fails explicitly. The format is tied to the pinned OpenMLS provider family;
there is no implicit migration or reconstruction from a public roster.

The host atomically saves the sealed record. This small-slice choice keeps one
protected state image; the SQLite transaction experiment remains a separate
candidate for larger durable state. Current snapshots do not include a delivery
outbox or invitation lifecycle. No rollback high-water mark is implemented, so
an older valid same-workspace snapshot is not detected. Process-death and
membership-transition atomicity need their own tests. Endpoint rotation/rekeying
and multiple local principals storing the same workspace are not supported by
the current Android store. Snapshot plaintext buffers and derived keys are
zeroized on drop; this does not claim all upstream provider allocations are
zeroized or protected from other code in the host process.

## Invitation bootstrap proof

`Workspace::join_checkpoint()` exports a bounded signed GroupInfo with its
public ratchet tree, only for a local administrator. It does not issue an
invitation. `JoinProof::from_trusted_checkpoint(workspace, digest, bytes)` requires
a digest from the trusted invitation channel; accepting a digest supplied beside
a peer's response defeats the trust boundary. The 64KiB bound is per checkpoint
or admission commit, not a scale guarantee or a selected JNI wire encoding.

`JoinProof::apply_add` verifies exact public MLS commit decoding/signature/epoch,
one Add, unchanged policy and committer identity, unique version2 member/endpoint
bindings, current-admin grant signature and redemption bound to the exact
KeyPackage. It merges only after verification. `matches_workspace` compares a
locally MLS-validated group with that branch, including context, confirmation tag
and ratchet tree. No OpenMLS objects or secret group keys cross this API.

New groups use public handshakes and Welcome ratchet-tree extensions; MLS
application payloads remain encrypted. Public here describes MLS wire format,
not permission to disclose roster metadata. The transport must restrict these
records to authorized encrypted channels. Saved groups keep their existing
configuration. No invitation UI, pending-join persistence, history transfer,
management replay or branch resolution is provided by this primitive.

## Incremental public verification

`MembershipVerifier::from_trusted_checkpoint(workspace, digest, bytes)` and
`apply_transition(authorization, commit)` implement the same exact-action checks
as `JoinProof`, without retaining an inline lifetime history. `epoch()` reports
the accepted public epoch; `matches_workspace()` compares the full resulting
branch with an independently validated MLS workspace. The caller supplies the
trusted checkpoint digest and retains accepted records separately for recovery.
This object does not contain group secrets, persist state, admit a member by
itself, or reconcile competing branches.

`JoinProof` composes this verifier with the existing bounded `DFJH` history
encoding. Existing Welcome/save interfaces remain compatible. History-serving
paths use the incremental verifier while traversing retained records. The legacy
inline record, checkpoint/commit byte bounds, provider snapshot and retained
reply limits still require migration before larger runtime populations work.

The `incremental_verification_has_no_workspace_lifetime_counter` check processes
128 role transitions in a two-member public roster, rejecting wrong actions and
replays. It isolates verification with real MLS commits; it does not demonstrate
128 members, incremental disk storage, or an upgraded Android runtime.

## Recoverable pending joins

`PendingJoin::from_invitation(invitation, checkpoint, endpoint, display_name)`
validates the signed invitation/checkpoint and owns a fresh member ID, signer,
KeyPackage and exact authorized redemption request. Save the
pending owner before transmitting `key_package()` or its redemption. Its
`seal`/`restore` use the same bounded encrypted provider codec as Workspace, with
a distinct authenticated `DFPJ` phase. Version2 plaintext starts with checkpoint
digest32, request length u32/bytes, checkpoint length u32/bytes, member profile,
KeyPackage length u32/bytes, then provider records. The pinned checkpoint is
retained so restart does not require refetching it from the issuer. Version1 records remain readable without an invented
request or authorization.
The 128KiB plaintext/256-record limits still apply; a public KeyPackage is capped
at16KiB. Restore validates the KeyPackage signature/lifetime, identity binding,
private bundle and signer. It never generates replacement keys.

`prepare_workspace(proof, welcome)` requires the original checkpoint anchor,
validates the Welcome in a bounded provider copy and invokes branch matching
before returning a Workspace. Rejected responses leave pending state reusable,
including failures after upstream KeyPackage consumption. The caller must save
the returned Workspace atomically before retiring the pending record or reporting
joined/ready. It must hold the credential lock and prevent concurrent owners.
This primitive leaves the pending owner unchanged and is not a durable transition
coordinator. Welcome size is capped at64KiB; larger groups need a separately
validated storage/framing design. Invitation transport/UI, expiry/revocation policy, admission response retention
and pending-to-joined host recovery remain integration work.

## Signed invitation and provisional admission

`Workspace::issue_invitation()` returns an Invitation and its signed public
checkpoint. Only current administrators may issue it. `export_secret_token()`
explicitly returns the bearer secret for authorized sharing; never log it.
The fixed293-byte `DFIV` v1 token contains workspace32, checkpoint SHA-25632,
issuer signing key32, invitation public key32, ordinary-member grant signature64,
checkpoint-binding signature64, and bearer seed32. The second signature binds
all preceding public fields. Parsing verifies both signatures and proves that
the supplied seed matches its public key. Checkpoint validation additionally
requires that issuer to be an administrator in the pinned group. The trusted
invitation channel establishes the initial intended workspace; self-consistent
signatures are not a real-world identity certification.

`PendingJoin::join_proof()` reconstructs the trusted starting proof from the
saved checkpoint. Its inline checkpoint shares the128KiB total snapshot limit;
larger rosters need a protected content-store reference.

`PendingJoin::admission_request()` returns the exact persisted `DFJR` v1 request:
public grant, redemption signature and exact KeyPackage. It contains no reusable
bearer seed. DFPJ v2 restoration revalidates that request against its saved
workspace, checkpoint and KeyPackage. `Workspace::prepare_admission` verifies
current issuer authority, signatures, workspace scope, authenticated remote
endpoint binding and duplicate membership before preparing one Add on a copy.
The actual staged commit must also pass the shared JoinProof policy verifier.
PreparedAdmission contains a candidate Workspace, commit, Welcome and public
authorization proof. The caller must atomically retain new state plus response
and commit history before adopting it or sending any response. The original
owner is unchanged. The candidate now contains that admission's reply and local
commit in its version3 snapshot. The host must save/read back that snapshot before
adopting it, then retrieve the retained response. The host transaction coordinator
and remote commit/history retention are not implemented yet.

The local journal never silently evicts: at most16 admissions and128KiB total
snapshot plaintext. Storage overflow must stop adoption/sending. This is a demo
ceiling; migrate to bounded transactional retention with an explicit safe pruning
policy before supporting larger groups. The local journal alone does not provide a complete trusted branch history;
version4 joined state now retains the verified history separately. Transport
retrieval, synchronization of later remote commits and checkpoint rollover remain
unfinished.

The grant is reusable ordinary membership only; expiry, individual-invitation
revocation and request-approval mode are not implemented. Requests to an already
admitted identity fail explicitly in prepare_admission. Before preparing again,
the host checks retained_admission(authenticated_endpoint, exact_request) on its
durably adopted owner; a hit returns the exact original commit/Welcome/proof.
A changed request misses; an endpoint mismatch rejects. Current issuer authority
and recipient membership are rechecked. No KeyPackage expiry revalidation is
needed for byte-identical retries of an already completed admission. Public checkpoint distribution/retention and routing hints are
separate from this codec and must work without the issuer online. No new Iroh
control channel or plugin onboarding UI is implemented by these methods.

## Application protection

`protect_application(context, payload)` creates an MLS private application
message and advances the sender ratchet. `unprotect_application(context,
ciphertext)` verifies it and returns the authenticated member ID, endpoint ID
and opaque payload. The author is independent of the transport peer. The caller
supplies the canonical expected routing context; equality with authenticated
MLS AAD prevents moving ciphertext to another context. Topic permission checks
and publication-ID deduplication still belong in the assembled fabric.

Bounds are12KiB payload,1KiB routing context and16KiB ciphertext. Application
reception rejects public handshakes, non-application content, invalid ciphertext,
context mismatch and cryptographic replay. No CoT, transport or UI type enters
this interface. Private recipient audiences require a suitable separate security
context; encrypting to the whole workspace is not private messaging.

Both operations mutate ratchet state. Persist the updated owner before exposing
outbound ciphertext or delivering inbound plaintext, and before further sends.
On any error, discard the owner and restore the last committed snapshot. Some
rejections occur after OpenMLS consumes a receive generation. Retransmission must
reuse the original ciphertext, not re-encrypt from an older snapshot. This API
does not implement an outbox, atomic application delivery, rollback protection,
unlimited reordering/catch-up or network publication. JNI now provides a staged
save/adopt boundary with Kotlin save/readback helpers. Connecting its protected
outputs to Node routing and the ATAK adapter remains to implement.

The host test `application_authentication_replay_and_restart` performs actual
invitation admission, bidirectional binary-message protection, authenticated
origin checks, maximum-size payload/context, wrong-context/tamper/other-workspace/
handshake rejection, sender restart and persisted receive replay rejection.
No Android/network result follows from this test.

Pinned OpenMLS0.8.1 `src/framing/private_message_in.rs:136` debug-asserts on AEAD
failure before returning `MessageDecryptionError::AeadError`. The root workspace
therefore disables debug assertions for **only the OpenMLS dependency** in dev
and test profiles, matching its release error path. Authentication checks and
fabric-owned assertions remain active. Cargo profiles belong to the consuming
workspace: another project embedding this crate must account for the same
pinned dependency behavior in its development builds. Reassess/remove the
workaround when upgrading OpenMLS; do not mistake it for a protocol change.

## Authenticated recovery offers

`RecoveryRequest` specifies workspace, author, epoch, canonical selection digest
and `(after, through]` range. The caller establishes these from accepted delivery
state; never copy them from an unverified offer. `sign_recovery_offer` commits the
current local author's MLS signing key to the exact ordered hashes of up to 32
(context, ciphertext) pairs. `verify_recovery_offer` binds the response to the
expected request and current verified member signing key. The verified value
borrows that membership owner, preventing its mutation while the value is used.

Call `verify_packets` on the entire response before advancing a disposable
cryptographic owner, then `verify_origin` on each decrypted application. Normal
routing-context validation, topic authorization and save-before-adopt/deliver rules
still apply. Hashing length-delimited context and ciphertext prevents substitution
or repartitioning. The offer has a separate signature domain from MLS and invitation
messages. It contains metadata, not encrypted content, and belongs only on an
authorized encrypted channel.

There is no fresh challenge: an authorized holder can retain a fixed-range offer
and serve it while the author is offline. It cannot pass an old offer off as a
newer or differently selected range. Offer replay for the same requested range is
intentional; application replay remains controlled by persisted MLS state.

This primitive authenticates a publisher's coverage claim; it cannot infer the
correct packet set from ciphertext or prove an honest retained index. Durable
index construction, unavailable-range responses, automatic retrieval, range
selection/cursors and transport/JNI integration remain unimplemented. It supports
only the current accepted epoch and does not repair membership transitions.

## Exact management verification

`verify_management(ManagementAction, commit)` checks one promotion, demotion or
removal against the current accepted workspace. IDs are stable member IDs, not
names or endpoint addresses. It validates current admin authority, exact proposal
shape, role delta, remaining administrator and unchanged unrelated policy, then
uses a disposable private MLS copy to authenticate membership/confirmation tags.
Public-only validation is insufficient for an existing member.

This API does not change the owner, generate a commit, persist history or settle
conflicts. Tests use explicitly test-only MLS merges after verification to check
second-admin behavior, removal key separation and revoked invitation issuers.
Do not call a successful guard a committed management operation. Integration must
preserve the existing save-before-adopt contract, extend public history beyond
ordinary Adds, and handle a locally removed owner as removed rather than active.

## Typed history and provisional management state

`MembershipAuthorization` carries either an ordinary invitation authorization or
one exact `ManagementAction`. `JoinProof::apply_transition` verifies and appends
it to the same public chain. Add-only DFJH v1 remains supported. DFJH v2 uses the
same workspace checkpoint anchor and adds a tag to every step: 0 plus the existing
160-byte admission proof; 1/2/3 plus member ID32 for promotion/demotion/removal.
Every authorization is followed by u32 commit length and exact public MLS bytes.
Both formats are limited to 64 steps and 64KiB; protected workspace snapshots keep
a separate 128KiB total plaintext bound. Tags identify intent, not authority.

`prepare_management(action)` returns `PreparedManagement { workspace, action,
commit }` without changing the original owner. `prepare_management_update` returns
a similarly provisional outcome for a receiver. Host save/readback must
precede adopting either result or distributing the commit. Candidate history
persists through the existing encrypted snapshot; no separate authority file is
introduced. A surviving receiver returns `PreparedManagementUpdate::Active`; a removed one
returns `Removed`. Persist the returned variant rather than reusing the old active
snapshot as a completed removal.

`membership_history` supplies verified mixed transitions for an older invitation.
The compatibility `admission_history` method supports Add-only histories and errors
when management support is required. Runtime transport must switch to the typed
method and validate the corresponding wire steps before management is exposed.
The staging check *(receipt retained in Git history)*
verifies promotion/save/restore and old-invitation admission with the creator
absent. Full security and runtime regressions are linked from STATUS.md.

## Removed membership records

`RemovedMembership` exposes only local member metadata, workspace/endpoint context,
accepted epoch and removal commit digest. Verified management reception creates
it; it cannot publish, decrypt, invite, manage or become a Workspace. `seal` and
`restore` use the existing storage protection with a distinct DFRM v1 family.
Plaintext is epoch u64, the existing bounded member-profile encoding, and removal
commit SHA-25632. Total sealed size is at most 397 bytes. No MLS or delivery state
is retained in this record. Wrong-family, wrong-context and malformed records fail
closed; neither an active snapshot nor a removal record substitutes for the other.

Atomically replace the active snapshot before retiring its live owner or reporting
removal. Normal restart must reopen that same record. The library cannot detect a
host deliberately choosing a separate older authentic backup. Explicit re-admission
and endpoint recovery remain application workflows, not record-format fallbacks.
The runtime consumes/shuts down an endpoint session when it restores DFRM, returns
`state: removed`, and rejects further requests on that handle. Close still releases
the retired handle. Live management notification/save/adopt and plugin presentation
must use this outcome before user-facing removal can be claimed.

## Provisional native state

`Workspace::provisional_copy()` isolates one operation from the accepted owner
without encoding a legacy snapshot or replaying membership history. Rejected
candidates are discarded. Persist the accepted candidate before replacing the
owner or emitting its output. Copies must never operate as independent senders:
they begin with identical sender counters and ratchets. Copy cost grows with
native state size; this is not an incremental provider transaction.

## Shared workspace names

`create_named(endpoint, member_name, Some(workspace_name))` establishes the
creator's shared name. Omitting it retains legacy unnamed behavior; existing
local catalog labels never imply administrator authority. A current administrator
may initialize an unnamed workspace through `prepare_workspace_name`.
`workspace_name` returns the accepted name or `None`. Validation rejects controls
and directional formatting in the original input, then trims surrounding
whitespace and enforces 1–80 Unicode code points and at most 320 UTF-8 bytes.
Names need not be unique and are never routing or member identifiers.

A name update is independent of the MLS epoch. `DFNM` version 1 records contain
workspace32, revision u64, parent digest32, author member32, accepted membership
epoch u64, SHA-256 of the TLS-encoded group context32, canonical UTF-8 name and
Ed25519 signature64 over the complete preceding bytes. Each record is bounded
at 533 bytes. The receiver requires exactly the next revision and its locally
accepted parent, an author who is still a current administrator, and matching
administrator authority/signature on the named accepted membership branch.
Replays, substituted intent and conflicting children do not replace an accepted
name. The signer need not be the original creator.

`prepare_workspace_name_update` and `prepare_workspace_name` return provisional
workspace owners. Existing encrypted provider persistence retains accepted state
under `data-fabric/workspace-name/current/v1` and individual next records under
`data-fabric/workspace-name/step/v1/` plus their parent digest. A name update does
not change membership, data keys, message counters or delivery history. Native
record storage has no fixed name-change count; legacy snapshot size limits still
apply to legacy exports. `next_workspace_name` returns one bounded next record
for incremental synchronization.

Invitations retain their existing formats. The issuer adds the current name,
revision and head digest as a GroupInfo extension (`0xff01`), outside the MLS
group context. GroupInfo is signed and the invitation pins its complete digest.
A new join takes its name baseline only from that invitation-authorized
checkpoint. A member helping admit the invitee cannot replace that baseline in
its Welcome. An older invitation may carry an older name; normal signed update
polling supplies later names after admission. A fresh invitation carries the
accepted name without including the full name history.

`DFNC` version 1 checkpoints reconcile those missing-record cases without
trusting historical authority. A current administrator signs the accepted name,
revision and head against the current membership epoch and group-context branch.
Any current member may relay the exact retained checkpoint, while a demoted or
removed administrator cannot sign or alter one. Acceptance advances only to a
newer revision and persists the number of skipped revisions so unavailable
history remains explicit. Competing name branches remain conflicts; a peer's
latest label never overwrites local state by itself.
