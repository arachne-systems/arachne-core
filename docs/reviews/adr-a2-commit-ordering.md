> Written by Claude (AI). Status: Proposed.

# ADR A2: Commit ordering by deterministic tie-break

Date: 2026-09-24. Scope: `arachne-security`, `arachne-runtime`. Source finding: A2 in
`docs/reviews/2026-09-24-architecture-review.md` (related: A3, B2, B3).

## BLUF

- Each node picks the same winner when two valid commits exist at one epoch. The rule is a
  fixed total order: **priority class first, then lowest commit hash**. Remove and Leave have
  the highest class.
- A node on the losing branch goes back to its saved state at the fork point and replays the
  winning steps. It does not need to rejoin, if the fork is inside the rollback window.
- A revocation on a losing branch is not lost. It travels as a signed **revocation order**.
  Any member can commit it on the winning branch. A node does not send data while it holds an
  uncommitted order.
- Only administrators commit Adds. Members commit a new **SelfUpdate** step for post-compromise
  security. The Iroh key signs the endpoint binding in each leaf.
- Formats change without legacy support. Old records are rejected.

## Context

Facts from the code (base `b06a72d`):

- Many administrators can commit management at one epoch (`management.rs:382`). Any member can
  commit an Add (`bootstrap.rs:~290-311`). Expiry is checked only by the committer, because a
  verifier clock check would itself cause forks (`invitation_controls.rs:145`).
- The runtime reports `membership_branch_mismatch` (`membership.rs:671`) and does not resolve it.
  A step that does not verify is dropped (`stage_gossiped_step`).
- The endpoint in the credential (`lib.rs:98`, `bootstrap.rs:115`) is not signed. `Leave` signs
  the full `GroupContext` (`management.rs:44`), so it is valid on one branch only.
- Members never commit an update path.

MLS cannot merge two commits from one epoch. One branch must lose, and its intents must be
applied again or dropped.

## Decision

### 1. Fork-choice rule

Each accepted step has a **fork key**. It is computed from the step alone, with no local state:

`ForkKey = (class, SHA-256(commit bytes))`. The lower key wins.

| Class | Steps | Why this place |
| --- | --- | --- |
| 0 Removal | Remove, Leave | Takes keys away from a member. It must never lose to a step that keeps access. |
| 1 Revocation | Demote, DisableInvitation | Reduces rights, but no member loses keys. |
| 2 Management | Promote, invitation create / approve / decline | Admin intent that does not revoke. |
| 3 Admission | Admission, AdmissionBatch | Adds keys. It can wait one round. |
| 4 SelfUpdate | Member self-update | Routine. It never displaces admin work. |

Classes 0 and 1 are carried as signed orders when they lose (section 3).

Rules:

- The rule applies at the **fork point**: the lowest epoch where two branches have different
  steps. Later steps and branch length do not count. "Longest chain" is not used, because one
  administrator could extend a branch to win.
- The hash part can be ground (a committer can try many path secrets). Only a committer of the
  same class gains from this. Classes 0 to 3 are admin-issued, so grinding gives no new power.
  Class 4 always loses to admin work.
- The fork key **always** decides the winner, also for a fork below the local settled epoch.
  Settlement (section 4) decides only **how** the loser moves: it switches if it still has a
  snapshot at the fork point; otherwise it becomes **orphaned** and needs a re-add (section 5).
  If settlement could veto the winner, two sides that settled on their own would each refuse
  the other forever.

### 2. Detection and branch switch

A node detects a fork in three ways:

1. A head or membership reply has an equal epoch and a different fingerprint (today's check).
2. A gossiped or pulled step fails verification because its parent epoch is lower than the local
   epoch. The node loads the retained snapshot at that epoch and verifies the step there.
3. A branch query (new wire message) shows a different step digest at some epoch.

Then the node finds the fork point with a `BranchQuery {workspace, from: settled_epoch, until}`.
The reply lists `(epoch, step_digest, fork_key)`, at most 256 rows. The node compares the fork
keys at the first different row. If its own branch wins, it does nothing; the peer switches.
If the peer branch wins, the node switches:

1. Load the sealed snapshot at the fork epoch F (state before the fork commit).
2. Pull the winning steps from F. Verify and apply each step with the current verifier.
3. Collect intents from the losing suffix: revocation orders go to `carried`; the node's own
   non-revocation actions go to `retry` (section 6).
4. Use stage, save, adopt, as for any membership step. The host saves the new workspace before
   it adopts it. The old branch is kept until the save is complete.
5. If the winner removes this node, the result is `RemovedMembership`, as today.
6. Announce the new head.

A node never commits on the losing branch after it knows about a winner.

```mermaid
sequenceDiagram
    participant A as Admin A (side 1)
    participant B as Admin B (side 2)
    participant Y as Member Y (side 2)
    Note over A,Y: Epoch E. Partition starts.
    A->>A: Remove(M) at E, class 0
    B->>Y: Promote(Y) at E, class 2
    Y->>Y: adopt E+1', publish object O
    Note over A,Y: Partition heals
    Y->>A: head E+1', fingerprint differs
    Y->>A: BranchQuery from settled epoch
    A-->>Y: rows: E -> Remove(M), class 0
    Y->>Y: class 0 < class 2: load snapshot at E, apply Remove(M)
    B->>B: same switch; retry Promote(Y) once, as E+2
    Y->>A: re-publish O under the winning epoch
```

### 3. Removal guarantee

Guarantee: **if one honest node adopts a Remove of member M, and the network heals before
`ORDER_WINDOW` more epochs pass, the converged group excludes M.**

Mechanism: a **revocation order**. It replaces the MLS sender check for class 0 steps.

```text
RevocationOrder {
  kind: Remove | Leave | Demote | DisableInvitation,
  target: member_id or invitation key,
  issuer: signature key (admin; for Leave, the target),
  anchor_epoch: u64,
  anchor_context: SHA-256 of the public GroupContext at anchor_epoch,
  signature: over "arachne/revocation/v1" || workspace || all fields above
}
OrderStep = RevocationOrder + anchor_proof: public steps from a common ancestor to the anchor
```

- Each class 0 and class 1 step carries its order. The commit sender can be any member. This is
  the model that Leave uses today, but it does not depend on one branch.
- The anchor uses the public `GroupContext` hash, not `epoch_fingerprint`. The fingerprint needs
  the epoch secret, and a public verifier does not have it.
- **Validity depends only on the chain**, never on local settlement, so all nodes agree:
  1. `commit_parent_epoch − anchor_epoch ≤ ORDER_WINDOW` (64).
  2. The anchor is on the verifier's chain, **or** `anchor_proof` holds the public steps from a
     common ancestor epoch C to the anchor. The verifier rebuilds the public state at C from its
     step history with `MembershipVerifier` (no secrets), replays the proof, and checks
     `anchor_context`. This covers a Remove made on the losing branch after the fork point, and
     an issuer promoted on the losing branch.
  3. The issuer was an administrator at the anchor (for Leave: the target signed).
- The check uses the anchor, not the current state. A concurrent Demote of the issuer therefore
  does not cancel a Remove that was valid when it was made. A malicious admin could remove
  members anyway, so this gives no new power.
- The last-admin guard applies at commit time. A carried Demote that would remove the last
  administrator is dropped and reported.
- **Carry-forward.** After a switch, each order from the losing suffix that the winner did not
  apply goes into `carried`, with its proof. The node commits it on the winner at the next
  epoch. Orders also travel by gossip (`DFRO`), so any member that holds one can commit it.
- **Send quarantine.** While `carried` holds a valid Remove or Leave order whose target is still
  a member, the node does not encrypt new application data. It still receives. The quarantine
  ends when the target is out of the roster, or when the order becomes invalid (window passed,
  or the check fails). An invalid order is dropped and reported to the host, so a node never
  stays quiet forever.

Why it converges, for a finite set of intents: each round of competing commits lands one step.
A carried Remove is class 0, so only another class 0 step can beat it, and that step removes a
member too. Class 1 orders win whenever no class 0 step competes. Each order is applied once
and never made again, so the process ends. When the network heals, each order reaches each
side. Limit: data sent inside a partition before the Remove reaches it is exposed to M. No
protocol can prevent this. The exposure lasts as long as the partition. An order older than
`ORDER_WINDOW` when it arrives is lost; the admin must issue it again, and the runtime reports it.

### 4. Retained state and settlement

- For each unsettled epoch, the node keeps a sealed snapshot of its workspace before the commit
  (existing `seal` and `copy_provider`). One snapshot per epoch is necessary. OpenMLS cannot
  process a node's own commit again, so replay from one old snapshot does not work.
- **Settled.** An epoch E is settled when either:
  1. each member of epoch E has reported a fingerprint at E or later that is on this chain
     (membership replies and heads already carry this data), or
  2. the node has adopted `ROLLBACK_EPOCHS = 64` more epochs, or the snapshots pass
     `MAX_ROLLBACK_BYTES = 16 MiB`.
- When E is settled, the node deletes snapshots at or below E. It keeps the step history.
- Cost: retained snapshots keep old epoch secrets. This lowers forward secrecy for the window.
  The snapshots are sealed at rest. A3's receive window for past epochs has the same cost and
  can use the same store.

### 5. Deep forks: orphan and re-add

If the node lost and has no snapshot at the fork point, it cannot switch. It becomes
**orphaned**: it stops sending, keeps its received data, and asks an administrator for
re-admission with a fresh KeyPackage. The same applies to a node that joined only on the losing
branch. There is no external commit: an external commit lets a node add itself, and a removed
member has the same old state as an honest one.

### 6. Application data from the losing branch (A3)

- Objects that this node published in losing epochs are re-encrypted and re-published under the
  winning epoch, after the send quarantine ends. The object id must not depend on the epoch, so
  receivers remove duplicates (A6 requirement).
- Objects that other members published on the losing branch stay in local storage with a
  `losing_branch` flag. The node does not forward them. Their authors re-publish them.
- This needs A3's per-epoch publisher log, keyed by `(epoch, fingerprint)`.
- The node's own lost non-revocation actions (for example Promote) are retried one time if they
  are still valid on the winner. Otherwise the runtime reports `action_lost` to the host.

### 7. Who may commit what

| Step | Committer | Authorization |
| --- | --- | --- |
| Remove, Leave, Demote, DisableInvitation | Any member | Revocation order |
| Promote, invitation controls | Administrator | MLS sender in authority set (as today) |
| Admission, AdmissionBatch | **Administrator only** (new) | Grant and redemption, plus `asserted_time` |
| SelfUpdate (new) | The member itself | Commit with an update path only |

- **Admin-only Adds.** This fixes expiry: the admission step carries the committer's
  `asserted_time` in the signed commit authenticated data. Each verifier checks
  `asserted_time < expires_at`. The check is deterministic, and it trusts the admin clock, which
  is already trusted. A verifier logs a warning (it does not reject) if the time is far from its
  own clock. Cost: a join needs a reachable administrator. Mitigation: promote one admin per
  team element.
- **SelfUpdate.** A new `MembershipAuthorization::SelfUpdate`. The step is an empty commit with an
  update path: no proposals (RFC 9420 does not let a committer include its own Update), no
  extension change, and the same credential and signature key.
  Runtime policy: send one each 24 h or each 10,000 sent objects. Rate limits are a local relay
  policy, not a validity rule, because a validity rule that differs between nodes causes forks.
- **Endpoint-signed credentials.** Each leaf carries a leaf extension `ENDPOINT_BINDING`: an
  Ed25519 signature by the Iroh endpoint key over
  `"arachne/endpoint-binding/v1" || workspace || member_id || MLS signature key`. The Iroh id is
  an Ed25519 public key, so `OpenMlsCrypto::verify_signature` can check it with no new
  dependency. The extension is in `RequiredCapabilities`. `binding()` and `apply_add_batch`
  reject a leaf without a valid binding. A change of endpoint is Leave plus re-add.

### 8. Wire and persisted changes

No migration. Pre-release rule: no legacy modes. Old records fail with
`workspace format not supported; create the workspace again`.

| Item | Change |
| --- | --- |
| History codec (`bootstrap.rs` `read_step`/`write_step`) | Version 3. Tags carry class. Tags 2, 3, 4, 6 (Demote, Remove, Leave, DisableInvitation) carry an `OrderStep`. New tag 12 SelfUpdate. Admission carries `asserted_time`. Versions 1 and 2 are rejected. |
| Credential identity | Prefix `data-fabric/member/v3/`, plus leaf extension `ENDPOINT_BINDING`. |
| Leave payload | Replaced by `RevocationOrder` (anchor, not full context). |
| Gossip head `DFMH` | Version 2: adds the fingerprint and the fork key of the head step. |
| Control wire | New `BranchQuery` and `BranchReply`. New gossip payload `DFRO` for revocation orders. |
| Workspace record (`records.rs`, `storage.rs`) | Adds `settled_epoch`, sealed snapshots, `carried` orders, `orphaned` flag. |
| Runtime states | `membership_branch_mismatch` becomes a trigger, not a final state. New: `branch_switch_staged`, `orphaned`, `send_quarantined`. |

## Test plan

All tests use in-process nodes and fixed seeds. Where hash order matters, the test builds
commits until it gets the order it needs, then asserts on it.

| ID | Test | Assert |
| --- | --- | --- |
| T1 | Three observers receive the same two competing commits in all 6 orders. | Same winner, same fingerprint. |
| T2 | Two admins commit Promote and CreateInvitation at epoch E. | Loser switches; fingerprints equal; loser's action retried one time. |
| T3 | Promote has the lower hash; Remove(M) competes. | Remove wins (class before hash). |
| T4 | Partition {A admin, X} and {B admin, M, Y}. A removes M at E. Side 2 goes to E+2. Heal. | All fingerprints equal; M not in roster; M gets `Removed` or cannot decrypt new objects. |
| T5 | Both sides remove different members at E (M1, M2). Heal. | Both removed; no node encrypts between the switch and the carried commit. |
| T6 | A removes M at E on side 1; B demotes A at E on side 2 and wins by hash. | M removed (anchor rule); A demoted. |
| T7 | Fork 65 epochs deep. | Loser is `orphaned`, never sends; admin re-add restores it. |
| T8 | All members report epoch E+1; snapshots ≤ E are deleted. Then a competing commit at E arrives, once with a lower and once with a higher fork key. | Lower key: receiver becomes orphaned (no snapshot). Higher key: receiver keeps its branch; the sender side switches. |
| T8b | A Remove issued on the losing branch after the fork point, and an order older than `ORDER_WINDOW`. | First is accepted by `anchor_proof` on every node; second is rejected on every node, and the quarantine ends. |
| T9 | Loser published O on the losing branch. | O re-published once under the winner; the removed member never gets it. |
| T10 | Member commits an Add; member commits SelfUpdate; SelfUpdate with extension change. | Rejected; accepted; rejected. SelfUpdate loses to an admin step at the same epoch. |
| T11 | KeyPackage with a wrong endpoint signature. | `apply_add_batch` rejects it. |
| T12 | Add with `asserted_time ≥ expires_at`. | Every verifier rejects it, not only the committer. |
| T13 | Property test: random commits in 3 partitions, random heal order, 200 seeds. | One fingerprint at the end; removed set ⊇ union of Removes that any honest node adopted. |

## Implementation steps

Each step is one small change with its own tests.

1. **Fork key.** New `crates/arachne-security/src/fork.rs`: `ForkClass`, `ForkKey`, `fork_key(auth, commit)`. Test T1 (pure part).
2. **Admin-only Adds and asserted time.** `bootstrap.rs` (`apply_add_batch` committer check), `invitation.rs` (add `asserted_time` to authenticated data), `invitation_controls.rs` (`check` gets the asserted time). T10 (Add), T12.
3. **History codec v3.** `bootstrap.rs` (`read_step`, `write_step`), `history.rs`, `records.rs`, `storage.rs`. Reject v1 and v2.
4. **Revocation orders.** `management.rs` (class 0 and 1 actions take an order; any member may commit; chain-only window; `anchor_proof` replay with `MembershipVerifier`), `history.rs` (rebuild public state at an ancestor epoch). Remove `leave_payload`. T6 and T8b (security part).
5. **SelfUpdate.** `bootstrap.rs` (new variant and verify), `management.rs` (`prepare_self_update`, `prepare_self_update_update`). T10.
6. **Endpoint binding.** `lib.rs` (`credential_identity` v3), `pending.rs` (KeyPackage gets the signed extension; the caller passes an Iroh signer), `bootstrap.rs` (`binding` checks it), `crates/arachne-node` (expose an endpoint sign function). T11.
7. **Snapshots and settlement.** New `crates/arachne-security/src/branch.rs`: `BranchState`, `prepare_branch_switch(fork_epoch, steps) -> PreparedBranchSwitch`, prune by settlement. Persist in `records.rs`. T8 (security part).
8. **Detection and switch in the runtime.** `arachne-runtime/src/membership.rs` (`agreement`, `stage_gossiped_step`, `finish_range_pull`), `wire.rs` (`BranchQuery`, `BranchReply`, `DFMH` v2), runtime state machine. T2, T3, T4, T7.
9. **Carry-forward and send quarantine.** `membership.rs` (commit carried orders, `DFRO` gossip), publication path in `arachne-runtime/src/lib.rs` (block encrypt while quarantined). T5.
10. **Re-publication and retry.** Runtime publisher log (after A3 per-epoch logs), `arachne-delivery` dedupe by stable object id. T9.
11. **Settle on observation.** `membership.rs` records each member's reported `(epoch, fingerprint)`. T8.
12. **Convergence test suite.** New `crates/arachne-runtime/tests/branch_convergence.rs`. T4, T5, T13.
13. **Docs.** `docs/security.md`: fork model, removal guarantee and its limit, forward-secrecy cost of the window.

Steps 1 to 7 are in `arachne-security` and do not need A3. Steps 8 to 12 need step 7. Step 10
needs A3.

## Alternatives considered

- **Single sequencer with failover.** Failover needs an election, and an election needs a quorum.
  A minority partition could not commit at all, also not a Remove. Failover without a quorum
  gives two sequencers: the same fork. The owner rejected it.
- **Longest chain, or a quorum vote per commit.** An admin can extend a branch on purpose to
  win. A vote fails in partitions, like the sequencer.
- **DMLS** (draft-kohbrok-mls-dmls). It lets members read concurrent commits of one epoch, but it
  does not choose the membership. OpenMLS 0.9 does not have it. Our snapshot window is a small
  subset of the idea. Look again when OpenMLS supports it.
- **Decentralized CGKA** (Weidner et al., CCS 2021). Handles concurrent changes by design, but it
  is not MLS and would replace OpenMLS. Too costly now.
- **Members keep the right to commit Adds.** Easier joins, but expiry stays a committer-only
  check, and a member removed on the other side can still add people. More admins is the
  mitigation.
- **External commit to rejoin after a deep fork.** A removed member has the same old state as an
  honest member, so it could add itself back. Admin re-add is used instead.

## Corrections found during implementation (steps 1 and 7, `b995fba`, `624c658`)

These corrections replace the text above where they conflict.

1. **Settlement.** Epoch E settles when every member of E reports E+1 or later. A report of E
   alone does not prove that the member merged the commit out of E. (Section 4 said "E or later".)
2. **Removed members** never report E+1, so an epoch whose commit removes a member settles only by
   the window.
3. **The real window** is smaller than 64 epochs when snapshots are large: 16 MiB holds about 24
   snapshots of bundle size (~656 KiB). Document the real window in `docs/security.md` (step 13).
   Test T7 holds only for small snapshots.
4. **Commit bytes** for the fork key are exactly the commit bytes stored in history. Every node
   must hash the same bytes.
5. **Never trust a peer's key.** Recompute the fork key from the verified step before a switch.
   A `BranchReply` can claim any class.
6. **Bind snapshots to epochs.** After unsealing a snapshot, check `epoch() == fork_epoch`.
7. **Keep the `DFBR` branch record inside the sealed workspace store.** The record is not
   authenticated by itself; only the snapshots in it are sealed.
8. **`fork_key` takes only an authorization already verified against that commit**, or a history
   tag could relabel a Promote as a Removal.
9. **Workspace-name records** are not MLS commits and have no class. Give them one if they ever
   become membership steps.

API note: `BranchState` uses `first_unsettled` (= `settled_epoch + 1`). `prepare_branch_switch`
takes no steps; unseal and replay belong to the wiring (step 8). The switched state keeps the
snapshot at the fork epoch F, so replay retains from F+1.
