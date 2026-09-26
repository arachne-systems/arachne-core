# H4: Core binding contract

## BLUF

Core owns the binding types and native candidate rules. The SDK can generate bindings from
Core metadata and add language conveniences. It must not copy Core enums, records, error
mapping, candidate checks, or storage commits. The public contract is API version 6.

The evidence report records the checks and remaining release gates. H4 does not change
the deployed tablet storage.

## Binding components

Enable `arachne-runtime/uniffi`. This also enables `arachne-api/uniffi`. Both crates own
UniFFI 0.31.2 metadata. No spike crate is in the production workspace.

| Core crate | Kotlin package | Swift module |
| --- | --- | --- |
| arachne-api | org.arachne.core.api | ArachneApi |
| arachne-runtime | org.arachne.core.runtime | ArachneRuntime |

The SDK builds the final library and owns library loading and packaging. Core configuration
sets no final dynamic library name. A binding generator can apply SDK naming choices to
methods. These choices must not copy the domain types. Core names the Kotlin native
`Client.close` operation `shutdown` because UniFFI owns the generated `AutoCloseable.close`.
Generate Kotlin and Swift without a whole-config override so each Core namespace applies.
UniFFI 0.31.2 does not insert Swift imports for these foreign records. H5 compiles both
generated Swift components in one ArachneSDK module and keeps their separate C FFI modules.
A top-level Swift `imports` configuration has no effect and is not included.

## Changes at the Rust boundary

- `Client::open` and `Client::open_in` return `Arc<Client>`. `open_in` takes an `Arc<Context>`.
- `Context::owned(limits, power, workers)` creates an owned runtime. `default_shared()` uses
  the process context. A host-supplied Tokio handle remains a Rust-only option.
- All client methods return `ApiError`. Use its variant and stable `ErrorCode`. The old
  `client::Error` and `ErrorKind` are removed. Use the exact code: for example, a mismatched
  freshness anchor reports `CandidateStale` (302), which the old broad kind grouped as storage.
  An operation racing `close()` returns `Closed`.
- Use one `Network` enum from `arachne-api`. `Tor` always exists. A build without Tor returns
  `Unsupported` (103) when a caller selects it.
- IDs use the Core ID types. `Key32` represents a fixed-length key or digest. It does not
  identify a member. The foreign form is validated hexadecimal text. Malformed custom IDs fail
  binding type conversion before a Core operation. They do not enter the domain error channel.
- `ClientConfig.secret` is an optional byte vector. Core validates its 32-byte length and
  returns `InvalidInput` (100) for malformed key material.
- Counts exposed to bindings use fixed-width integers. A native collection length uses `u64`.
- `install_member_policy` accepts `&[String]`. Optional workspace names are `Option<String>`.
- `set_deadline(&self, ...)` is the binding operation. Rust's `with_deadline(Arc<Self>, ...)`
  remains a convenience.
- `default_limits`, `default_transport_options`, and `default_client_config(network)` return
  native defaults. Language adapters need not duplicate the default numbers.
- `Capabilities.limits` comes from the client's context. It is not a process-wide guess.
- `Event::ALL` lists the event contract. Public enums allow future Rust variants.

## Native storage and candidates

Set `ClientConfig.storage` before opening the client. Foreign callers use
`StorageConfig.open_sqlite(directory, root)`; the root must have exactly 32 bytes. Memory
providers and custom provider traits remain native Rust seams. Storage configuration is an
opaque shared object. A foreign caller cannot extract the storage root from it.

Candidate objects have private state. Each candidate is bound to its client, kind and staged
token. The native adopt operation saves the exact state, reads it back, and only then makes
it live. Candidates cannot be constructed or edited by SDK code. A successful adopt consumes
the staged authority; a replay fails. `discard()` is the explicit cancel operation.

`FreshnessAnchor` uses its existing 40-byte encoding as the foreign custom type. Do not
rebuild this encoding in an SDK. Use the Core value and return it unchanged.

## Typed lifecycle operations

| Operation | Result | Application action |
| --- | --- | --- |
| drive_join | JoinProgress | Read status, or adopt the returned JoinCandidate. A Joined result is already durable. |
| request_admission | AdmissionResponse | Read status, or pass the opaque AdmissionGrant to stage_join_grant. |
| drive_workspace | WorkspaceProgress | Read activity, presence, notices and the native operation outcome. |
| poll_membership_update | optional MemberUpdate | Read metadata. Pass the opaque object to stage_membership_update. |

`AdmissionGrant` preserves the entire received membership history. A host cannot alter a
commit or omit a management step. `MemberUpdate` preserves a received membership/name
operation until the native stage operation verifies it. Both objects are bound to the client
that received them. They do not grant authority before staging and durable adoption.

An `AdmissionNotice` can lack an attempt ID before the request enters the durable approval
queue. The approval page still contains complete durable `AdmissionApproval` values.

The activity projection uses the common Core helper. H1 adds `Recovering` reasons
`branch_orphaned` and `branch_send_quarantined` to that helper. A recovered roster alone does
not mean that a member can send.

## Retained content and resources

The typed client exposes direct gap discovery, direct recovery, authenticated miss staging,
recovery cutoff discovery, and current-view fetch/poll/stage/adopt/cancel. These are the same
native operations as the current dispatcher. Current-value metadata preserves selector,
replacement key, expiry and tombstone. Recovery can use an authorized holder.

`ResourceRequest` and `ResourceStatus` expose the existing authenticated blob transfer
service. Paths are strings at the foreign boundary. `root` is the blob cache directory. It does not
confine file access. The host selects absolute source and target paths and must check the
content audience. Native membership and revision checks and the peer-bound read grant still
apply. No new catalog store or transfer protocol is selected in H4.

The typed protected publication, durable inbox and MoQ operations remain available. Core
has no microphone, channel, floor, or audio policy.

## Fixtures and JSON removal

`test-fixtures` enables caller-made policy, unprotected publish/poll and `harness`.
`debug-rig` enables the raw control exchange operation. A production request decoder rejects
these operations when the matching feature is off. Production SDK builds must enable neither.

The JSON dispatcher remains for existing SDK and qualification callers. H5 must remove SDK
calls and demonstrate generated-language equivalents before the dispatcher is deleted. The
remaining Core integration fixtures then migrate to typed operations or explicit test support.
Do not remove the dispatcher while a shipped adapter still uses it.

## Device upgrade gate

The deployed tablet build uses an older native record format. Moving its database path is
not an upgrade. SQLite metadata, encrypted heads, logical record framing, the stored root
binding and the durable inbox format changed before H4. The old inbox DFIC v5 is not accepted
by the new v6 reader.

Before the new Core is deployed to existing app data, provide and prove an authenticated,
one-time native upgrade. Preserve endpoint identity, workspace authority, storage roots,
freshness anchors, counters, retained content and pending inbox state. Prove crash recovery
for the upgrade. No compatibility reader, data clear, extra app package or replacement
workspace is included in H4. The current rig remains on the compatible build.
