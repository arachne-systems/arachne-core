# Main and feed branch import audit

## BLUF

The integration history already contains the Core implementation from local
`main`, with later API and storage changes. It also contains the feed branch
operations. Preserve the current code and record both old histories as merged.
Do not restore the old JSON client or host-owned snapshot API.

## Sources and method

- Main: `e410313ec750d4f6521053800361bc180bc94473`.
- Imported source root: `a694262` (an ancestor of `integrate/wave1`).
- Integration checkpoint before this audit: `3ab4486`.
- Feed branch: `codex/feed-publication-api`, ending at `2f86d88`.

Main and the import root have separate Git histories. A tree comparison shows
that only 45 files differ between them. All other main file blobs are present
unchanged at the import root. The audit reviewed every changed production
source file. The later integration history changes those imported files.
The machine receipt beside this note records the exact tree comparison.

| Main to import change | Result |
| --- | --- |
| Delivery wire bounds | Reject sequence overflow; add its regression. |
| Node connections, budget and endpoint | Add caller-selected relays and online qualification. |
| Runtime client | Add typed admission, candidates, recovery and metrics. Connectivity delegates to the richer metrics result. |
| Runtime dispatch | Add bounded admission result push, candidate discard, staged administrator handoff and recovery feedback. Retain the prior reply behavior in shared helpers. |
| Membership | Share the offer builder, require the handoff ACK and retain the peer's authenticated head for catch-up. |
| Admission waiters | Keep the peer route after a held request expires, for a bounded result push. |
| Security invitation | Add a type alias and use verified history indexes. |
| Persistence and activity | Simplify lazy defaults and formatting; retain the same checks. |
| Package files and documents | Add package metadata, notices and concise guides. |

The later removal of `runtime/src/protected.rs` and `delivery/src/receive.rs`
is not a missing import: their exact main blobs exist at `a694262`, and later
commits replace their organization. Current publication, receive and recovery
operations live in the runtime `ops` modules. The old OpenMLS upgrade fixture
also exists in that ancestor. The native encrypted storage format replaces
that old sealed-provider import contract; H2 tests the current store contract.

The old `CORE_STATUS.md` and large development, domain and security guides
were replaced at the import root. Current `docs/architecture.md`,
`integration.md`, `delivery.md`, `security.md`, `development.md`, and the work
tracker are the maintained guides. Do not restore old API claims beside them.

## Feed API mapping

The feed branch changes only `client.rs` and its public exports (273 additions,
six deletions). The integration client has these operations:

| Feed branch operation | Current equivalent |
| --- | --- |
| Install owner policy | `Client::install_workspace_policy` |
| Stage opaque feed content | `stage_protected_publication`, including the workspace check |
| Current value metadata | `stage_protected_publication_with_current` |
| Commit outgoing content | `adopt_protected_publication` with an opaque candidate |
| Join with peers | `begin_join` / `begin_join_with_peers` |
| Maintain membership | `drive_workspace`; authenticated catch-up is internal |
| Service identity | `use_service_profile` |
| Restore stored workspace | `restore_workspace` with Core-owned storage |
| Enable inbox | Automatic on workspace commit and restore |
| Save host snapshot bytes | Replaced by the H2 native store transaction and candidate handle |

The Core payload remains opaque. CoT decoding, position and map objects stay
in ATAK. The old convenience JSON loop is not an additional required feature.

## Merge and validation rule

Use an `ours` ancestry merge for these two audited old histories. This records
their lineage and keeps the newer integration tree. It does not publish or
move main. A full integration suite is required after the remaining H packages
merge; this content audit alone is not a runtime test result.

## UniFFI prototype history

`9c0fa81` already imported `docs/reviews/spike-a1-uniffi.md` unchanged from
`85ae3e2`. H4 supplies the optional Core derives, typed client, ID lifting and
Kotlin shutdown rename. H5 carries the Go discriminant generator correction
and runs the four production language clients. An ancestry merge records
`spike/a1-uniffi`; it does not restore the throwaway client crate. The report
now identifies the old reproduction commands as historical evidence.
