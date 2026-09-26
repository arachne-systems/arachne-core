# H2: storage and candidate changes for the SDK

## BLUF

Core owns each workspace store. The SDK supplies the directory, storage root,
and endpoint identity before it creates or joins a workspace. Core saves each
candidate, reads it back, and then adopts it. The SDK must remove snapshot
save and import paths. These changes are not compatible with the old API.

## Client and storage

| Member | Required SDK change |
| --- | --- |
| `ClientConfig::storage: Option<StorageConfig>` | Set storage before `Client::open`. `None` permits an endpoint, but workspace create, join, and restore fail with `WrongState`. |
| `StorageConfig::sqlite(directory, root)` | Supply an existing private directory and a protected 32-byte storage root. The root is separate from the endpoint secret. Core names each file from its workspace ID. |
| `StorageConfig::new(provider, root)` | Rust hosts can supply a `StorageProvider`. Generated bindings need a concrete storage constructor; do not export this Rust trait as a foreign callback. |
| `StorageConfig::with_anchors(anchors)` | Use a platform store that an attacker cannot roll back with the database. Core writes the next anchor before the record commit, then confirms it. Restore requires a matching anchor. |
| `Client::restore_workspace(workspace, expected)` | Pass the workspace ID and an optional `FreshnessAnchor`. Do not pass snapshot bytes. Handle `RestoredWorkspace::Active`, `Joining`, and `Removed`. A removed result ends the session. |
| `Client::record_freshness()` | If the platform does not implement `AnchorStore`, save this anchor outside the database after each operation that can commit. Supply it at restore. An anchor is 40 bytes: an 8-byte revision and a 32-byte digest. |
| `Client::create_workspace` and `begin_join` | Results are saved before these methods return. The caller does not perform a later save. |
| `Client::reset_workspace()` | Core writes a terminal reset marker. The host must not delete or replace the record database to imitate reset. |

The same endpoint identity is required to restore its workspace. A changed
endpoint returns `WrongState`; it does not make the database unreadable.
Keep the storage root and endpoint secret as separate protected values.

Without an external freshness anchor, restore cannot detect a whole-database
rollback. A file beside the database does not provide that guarantee.

## Candidate objects

The candidate constructors and token bytes are private in the typed API.
Each object belongs to one client and one operation kind. A second adoption
returns `CandidateStale`. A different client returns `WrongState`.

| Object | Adoption method |
| --- | --- |
| `WorkspaceCandidate` | `adopt_admission(&candidate)` for an admission, management action, name change, or self-update |
| `InvitationCandidate` | `adopt_invitation(&candidate)`; only this result releases the invitation |
| `RemovalCandidate` | `adopt_removal(&candidate)`; this ends the session |
| `JoinCandidate` | `adopt_join(&candidate)` |
| `PublicationCandidate` | `adopt_protected_publication(&candidate)` |
| `ProtectedReceptionCandidate` | `adopt_protected_reception(&candidate)` |
| `RecoveryCandidate` | `adopt_recovery(&candidate)` |

Each candidate has `workspace()` and `discard()`. Recovery also has
`publication_count()`. Dropping an unused Rust candidate discards it. Generated
objects must retain that lifetime behavior. `discard()` returns `false` if the
candidate was already used or is no longer staged. Core refuses to discard a
candidate after it reached storage.

A failed commit or read-back leaves the storage result uncertain. Core blocks
further state changes. Close the client and restore the workspace. Do not
repeat the cryptographic operation with the old live state.

## Temporary JSON surface

H4/H5 must remove this surface after its consumers use the typed API.

- Attach storage with `attach_storage(handle, StorageConfig)` before a
  workspace operation. `enable_record_storage` and public `save_candidate`
  are removed.
- Stage replies carry `candidate`. Adopt requests take `candidate`. They do
  not carry `snapshot`. `discard_candidate { candidate }` discards that token.
- `restore_workspace` takes `workspace` and optional `freshness`. It does not
  import bytes. The `seal_workspace` and `seal_pending_join` operations are
  removed.
- `execute_stored` remains only as the separate binary Welcome argument to
  `stage_join`. It no longer routes candidate or workspace snapshots.

## Stored record bounds

The store limits each physical record to 1 MiB. The runtime splits logical
values over 512 KiB into parts in the same authenticated commit. Restore joins
the parts before it decodes a security record. This also applies to branch
records, including H1 rollback snapshots and carried revocation orders.

Store format 1 and runtime record format 1 are explicit. There is no reader
for a store that predates these versions. The migration hook accepts only
declared format upgrades; it is not a legacy import path.

## Workspace driver

`drive_workspace` saves and adopts its own self-update in one call. It then
announces the committed history. It no longer returns `self_update_offered`,
`self_update_pending`, or `self_update_refused`. It returns
`self_update_committed` after the local save succeeds. Other members catch up
through the membership protocol. H1 fork choice resolves concurrent updates.

The candidate guard still blocks unrelated operations while a host has an
explicit staged candidate. A failed save still requires close and restore.

## H4/H5 follow-up

- Increment `API_VERSION` for the final breaking surface. It is still 5 on
  the A5 branch before H4.
- Export a concrete directory/root storage configuration and freshness data
  through generated bindings.
- Export each candidate as an opaque object. Do not expose its token or
  translate it back to snapshot bytes.
- Regenerate all bindings together. Retain the storage-failure and candidate
  error-code tests across each language boundary.
