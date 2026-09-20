# Portable Arachne runtime

The runtime composes `arachne-node`, `arachne-security`, `arachne-routing` and
`arachne-delivery`. Android calls it through `fabric-android`; native processes
can call it directly without JNI, Android or CoT. Payloads remain opaque bytes.

Native consumers should use the typed blocking `Client` seam. It covers
endpoint/workspace state, roster and invitation projections, opaque pub/sub,
delivery/recovery results, connectivity and cancellation/shutdown. The existing
request dispatcher remains available to adapters that have not migrated:

- `create` opens a session with an optional workspace-facing endpoint seed.
- `describe` returns its endpoint metadata.
- `execute` accepts bounded JSON requests and returns JSON responses.
- `execute_stored` takes JSON metadata and a separate binary snapshot, returning
  metadata and snapshot separately.
- `close` stops tasks and releases the endpoint and runtime.

Calls block and must run outside an asynchronous runtime. Handles are local to
this process; closing one invalidates it. Session operations serialize under its
lock. The process currently supports eight sessions, each with two runtime worker
threads. This is an explicit capacity ceiling, not a thousand-node design claim.

The request schema remains in `src/lib.rs::Request`. This is a prototype facade,
not a stable versioned wire protocol. Follow the existing stage/save/readback/adopt
transactions: the caller owns durable storage and must commit the exact returned
snapshot before adoption releases protected effects. Delivery intent remains
pending until the application succeeds and its acknowledgement is saved/adopted.
`close` is not a persistence operation. Never clone or roll back a sender's stored
credentials/state to create another endpoint.

Admission requests are identified by the authenticated endpoint plus exact
request bytes. `poll_admission` returns one bounded batch or one
`approval_requested` item; approval-required items remain in the Rust runtime
until the workspace transition is adopted. Hosts can enumerate them with
`list_admission_approvals` (pages are limited to 64), acknowledge presentation
with `acknowledge_admission_approval`, and approve or decline using the returned
`attempt_id`. A retry after an approval transition re-evaluates the workspace
state, so a stale local pending entry cannot hide an approved request.

`stage_network_publication` accepts optional `recipients`: an empty list is an
ordinary topic publication; a nonempty list is a sorted, unique set of current
workspace member IDs. The runtime resolves those IDs from accepted MLS roster
bindings, authenticates the recipient scope with the publication, and sends only
to the selected current Iroh endpoints. It rejects unknown, duplicate, unordered
or self recipient scopes without broadcasting. Direct publications use the
independent object envelope so skipped members do not miss a shared MLS
application-ratchet generation. They remain excluded from ordinary group recovery
so their audience cannot widen. With object delivery enabled, each
publisher/revision/topic/audience stream has its own signed sequence
and bounded durable cache. A recipient that observes a gap queries only the author
and other intended recipients, buffers later objects until the range completes,
and durably reports a miss before releasing later objects if no authorized cache
can supply it. Like Zenoh's default advanced-subscriber recovery, a missing final
object is not detectable until a later sequence arrives; periodic private
heartbeats remain a separate follow-up.

The shared integration check uses real Iroh peers, authorized admission, protected
publication, retention, pending replay, acknowledgement and restored snapshots:

```sh
cargo +1.98.0 test -p arachne-runtime --locked --offline
```

A service using this dispatcher must follow the same authorization and save
contract. The extraction alone does not implement a feed, existing-member epoch
synchronization, feed discovery or subscriptions in the plugin.

The continuity integration also separates the transport holder from the original
publisher. A modern object-delivery receiver can persist an exact signed recovery
range with a finite `retain_until`, restart, and serve that proof after the
publisher disconnects. The requester supplies the original member ID separately;
the runtime rechecks the holder, author, requester, epoch and topic policy before
returning the original bytes. It never reattributes the publication to the holder.

`stage_management` accepts an action with `kind` (`promote`, `demote`, or
`remove`) and a stable 32-byte `member` ID. The core verifies current administrator
authority and the exact change. Save/readback the returned snapshot, then call
`adopt_admission`; only adoption releases the serialized membership `step`.

For an existing member, `stage_admission_update` accepts one `step`: `commit`
and exactly one of `authorization` (admission) or `management` (typed action).
The complete signed transition is verified before staging. Active recipients
save/readback and `adopt_admission`, then reconfigure policy/data for the new epoch.
Removed recipients receive `removed: true` with an authenticated removal snapshot;
adoption retires the session and returns `state: removed`. Restoring that record
also retires the session. Hosts must display removal without configuring data.

`fetch_membership_update` queries a specified admitted `peer`;
`poll_membership_update` returns availability or one retained typed transition.
The `poll_admission` control pump serves queries, returning `membership_replied`.
Current members can retrieve retained verified history. A former member can fetch
only its own removal from a parent state that proves its endpoint binding; that
reply does not disclose subsequent epochs. Missing predecessor history is not
repaired by this exception. `membership_unavailable` does not establish consensus.

Pending application work must be acknowledged and active recovery finished or
cancelled before an epoch transition. Consequently, removal reception with pending
work can still be delayed; this is not a proven removal-liveness guarantee.
Conflicting membership branches are not automatically reconciled.

`poll_workspace_presence {announce?: bool}` drives bounded workspace reachability
notifications independently of application topics. Call it regularly while active;
set `announce: true` on activation or network return. The shared `poll_admission`
pump serves `DFPR` requests and returns `presence_replied`; an accepted notification
may produce a `sync_peer` in the next presence poll. Prioritize ordinary verified
membership retrieval for that peer (`fetch_membership_update` can explicitly
`replace_pending`). Notifications never adopt a roster or grant authority.

`member_roster` includes transient `presence`: `self`, `unknown`, `reachable`, or
`stale`. Reachability expires after 70 seconds without a fresh authenticated
observation; saved memberships do not restore presence. Immediate lifecycle
announcements handle activation and network return; 30-second direct safety rounds,
bounded to 16 concurrent requests, repair missed notifications. This is
not gossip or measured large-workspace convergence. Native PLI policy is unaffected.

`tests/management.rs` exercises promotion, save/adopt rejection, restart, an older
invitation redeemed while the creator is closed, and terminal removal retrieval
over real Iroh. It does not prove Android UI or filesystem power-loss behavior.

`cargo run -p arachne-runtime --example session` runs a local JSON-lines adapter.
Create with `{"op":"create_session","secret":[32 bytes]}` for isolated/direct
fixtures or add `"network":"wan"` for LAN discovery, public endpoint lookup and
relay fallback; thereafter send
`{"request":{runtime request},"snapshot":[optional bytes]}`. Responses carry
metadata and encrypted snapshots. This is a harness/source-adapter driver,
not a network API or automatic persistence layer. Keep both pipes private and
persist through the documented save/adopt contract. Close with
`{"op":"close_session"}`. The service-admission harness provides an executable
example with repository-local private state and a separate public receipt.
`scripts/run-adsb-feed.py --join` consumes the current compact invitation through
hidden/stdin input once, then uses the same stored identity on ordinary starts.


Network admission sends a `DFJA` version 1 wrapper containing the saved redemption
request and its pinned public checkpoint. Before staging an Add, the receiver
validates the authenticated endpoint, invitation grant and complete ancestor chain.
The prospective serialized reply is paged under the existing 128-KiB control
response bound before its owner can be adopted. Missing history fails without
changing the accepted owner. A saved reply contains `commits` in verified order
through the retained Welcome's epoch; a retry must not append later epochs to that
Welcome. The joiner fetches additional `DFJP` history pages when needed, verifies
every step, and only then adopts membership. No bearer private key or application
history is returned by this history mechanism.

The explicit 500-member capacity check is runnable locally:

```sh
taskset -c 0-3 env \
  ARACHNE_ADMISSION_BATCH_MEMBERS=500 \
  ARACHNE_ADMISSION_BATCH_SIZE=16 \
  cargo test --release -p arachne-security --test admission_harness \
    admission_batch_harness_scales_to_thousands -- --ignored --nocapture --test-threads=1

taskset -c 0-3 cargo test --release -p arachne-runtime --lib \
  admission_history_pages_handle_500_member_burst -- --ignored --nocapture --test-threads=1
```

The first command validates all 500 lower-library join proofs; the second covers
the runtime wire envelope and paged history through an independently validated
joined workspace. These are local capacity tests, not proof of 500 simultaneous
Android devices or a particular Wi-Fi/relay network.

`tests/offline_invitation.rs` closes the issuing admin, restores an ordinary helper,
and redeems the original older invitation over real Iroh. It checks the missing
chain and tamper rejection. This proves the core/runtime operation with a supplied
helper route. Automatic helper discovery, safe route fallback and the corresponding
plugin workflow remain unverified. Network admission with this wrapper requires
updated peers; legacy raw/local admission remains a compatibility path and does
not supply the history preflight guarantee.


`issue_invitation` now also returns up to seven cached member `routes` filtered
through the verified roster. They are reachability hints, not current-online
claims. `request_admission` returns `state: admission_not_sent` when the control
request could not have been written (or no route existed). Other errors can have
unknown outcomes. Clients must save the attempted peer before calling, preserve
uncertainty across restart, and never use a later non-send to erase an earlier
uncertain attempt. The plugin's pending catalog v3 implements this pin; old pending
records are conservatively pinned. The controller instrumentation test exercises
closed-admin fallback and restart pinning; actual ATAK UI proof is separate.


`member_roster` returns stable workspace member IDs, endpoint bindings, current
administrator roles and independently verified display names. Optional `profiles`
imports up to 64 signed profile records (389 bytes each); invalid or no-longer-member
records are discarded, never used as authority. The returned signed records may be
cached by the host. Unknown names remain null. Roles always come from the accepted
MLS roster; neither cached names nor peer-supplied role labels determine authority.

DFMQ v2 membership queries carry the requester's self-signed profile. Authorized
current members receive cached signed profiles with the membership reply; former
members retrieving their own removal receive no profiles. V1 queries remain
readable but do not exchange names; old responders reject v2 rather than negotiate
a downgrade. Use matching builds for this prototype. Profiles bind workspace,
stable member ID and name to the member's MLS signing key. They do not contain an
epoch, so names survive role changes when the same member/key remains admitted.
Name revision ordering and rename UI are not implemented. Replayed valid names
must not be represented as proof of freshness. Profile exchange is currently
bounded to 64 names; pagination and larger-workspace measurements remain open.

## Native record persistence

A native client can opt into session-owned encrypted SQLite records:

1. Create or restore the legacy workspace or pending join as usual, then call
   `enable_record_storage(handle, private_path, storage_root)`. It atomically
   saves the owner/delivery state or pending identity; an initialized database cannot be replaced
   by this migration method. Keep the host endpoint credential lock throughout.
2. Stage operations normally. The binary `snapshot` slot now carries a random
   37-byte `DFRC` v1 candidate token, not a restorable snapshot. Never write it as
   a replacement legacy workspace file.
3. Call `save_candidate(handle, token)`, then the matching `adopt_*` request with
   that token. Adoption fails until the matching native transaction commits.
   Saving is idempotent and does not send, reply, adopt or deliver to the app.
4. On restart, create the same endpoint and call `restore_record_storage` with
   its path, storage root and expected workspace. Do not load a legacy file first
   or fall back if this fails. `seal_workspace` is disabled in this mode.

The runtime keeps security records, publisher/receive state and the object inbox
in one authenticated atomic record set. `runtime/token` identifies the accepted
commit. Terminal removal replaces everything with the token and protected removal
record; reopening consumes the session. A crash after commit and before adoption
restores the committed candidate. Delivery acknowledgement remains a separate
saved operation after the application accepts the stable object identity.

The JSON-lines session example exposes `enable_record_storage` and
`restore_record_storage` with `path`, `root`, and (for restore) `workspace`;
`save_candidate` takes `token`. These are private local harness commands. Never
log their credential-bearing input. Native security records never cross this
interface. In legacy mode the existing caller-owned snapshot contract remains.

Host catalog migration is still required before enabling this in ATAK. Pending
join cryptographic state can migrate as a protected `runtime/pending` record.
Successful admission atomically replaces it with active security records; restart
before commit retains the same pending identity and after commit restores the
admitted owner. Unknown-outcome/route metadata retains its existing host
persistence and must be reconciled with that authoritative lifecycle. The host must durably select the
native backend and reject fallback after migration/removal, including when the
database is missing. This API does not itself migrate the Kotlin catalog or
remove legacy files. Complete-database rollback still needs an external anchor.

`tests/native_persistence.rs` verifies a real runtime owner with 100 locally
orchestrated admissions, independent Welcome validation, constant-size candidate
tokens, commit-before-adopt rejection, restart at 17/65/100, pending inbox migration,
acknowledgement, and terminal removal. It is not a 100-endpoint network test.
The native inbox attachment remains bounded; membership/control paging and
measured delivery/resource capacity remain separate work.

`native_pending_join_keeps_identity_until_atomic_admission_commit` checks pending
restart, abandoned candidate retry, old-token rejection, and commit-before-adopt
restart into membership. The pending record still uses its bounded compatibility
encoding internally; checkpoint/Welcome/control-message paging remains necessary.

For `stage_join`, `execute_stored` may carry the Welcome in its binary argument
while metadata supplies only `op` and `commits`. An inline `welcome` and a binary
Welcome are rejected together, including an explicitly empty inline field. The
existing 64KiB Welcome bound still applies; the JSON request bound is unchanged.
Legacy inline requests remain supported. This avoids JSON byte-array expansion
at the local/native seam; it does not page network admission replies or history.

## Shared workspace name lifecycle

`create_workspace` accepts optional `workspace_name` separately from the member's
`display_name`. Creation, invitation issuance/inspection, pending joins, adopted
workspaces, restores and `member_roster` return `workspace_name` (null for legacy
unnamed state). The stateless `inspect_invitation` Rust/JNI entrypoint accepts
`{invitation, checkpoint}` and verifies the invitation-pinned name before any
endpoint or pending membership is created. Existing invitation transport versions
remain valid; invitation review describes its signed checkpoint, which can be
older than the current workspace.

`stage_workspace_name {workspace_name}` stages a current administrator's rename.
`stage_workspace_name_update {name_record}` verifies a received signed change.
Both use the existing durable save then `adopt_admission` lifecycle. The runtime
copies publisher, receive and object-inbox state unchanged; legacy candidates
remain sealed delivery bundles when those attachments exist. The MLS epoch and
routing revision do not advance, and pending application data stays readable.

DFMQ v3 adds the requester's accepted name head to the existing membership/profile
query. After membership agreement, a peer can return one bounded next name record.
`poll_membership_update` reports `workspace_name_update_available` with
`name_record`; callers stage, persist and adopt it, then poll again as needed.
In-flight requests bind both membership epoch and name head. Older replies become
`membership_update_stale` when either accepted value changes. Old query formats
remain readable. Unknown/missing name ancestry is `workspace_name_unavailable`;
an incompatible known revision is `workspace_name_conflict`. These are
synchronization observations and never authority to replace local state.

The [security naming contract](../arachne-security/README.md#shared-workspace-names)
records the current authority and checkpoint-reconciliation limits. #52 remains
open for those paths and the full native acceptance matrix.
