# Delivery semantics

This page is the delivery contract of `arachne-delivery` and the runtime
object path. It covers the three modes: **group**, **direct** and
**current**. The tests listed at the end check each rule.

## BLUF

- Delivery to the application is **at least once**. An object stays pending,
  also across restarts and epoch changes, until the application acknowledges
  or rejects it.
- Duplicates are removed per author and epoch by a bounded replay window, and
  across epochs by the publication id.
- There is no total order. Objects of one scope come in author order when they
  are pending together. Direct objects wait behind a gap.
- Loss is possible. Recovery from the author or a holder closes gaps inside
  bounded retention. A gap that cannot be recovered is reported, never hidden.
- A membership change never waits for the application. Pending work, replay
  state and publisher history move to the new epoch.

## Terms

| Term | Meaning |
| --- | --- |
| Object | One signed, encrypted publication (`DFSO` v2). It decrypts without other state. |
| Author | The member that signed the object. It must be a **current** member when the object is accepted. |
| Epoch | The MLS epoch the object was made in. The author always uses its current epoch. |
| Counter | The author's sender counter in that epoch. It is shared by all topics and audiences of the author. |
| Publication id | 16 bytes chosen by the application. Stable across retransmission and re-publication. |
| Scope | (author, policy revision, topic, recipients). Ordering and fairness apply per scope. |
| Receive window | The current epoch and the `RECEIVE_EPOCHS` = 4 epochs before it. See [security](security.md#receive-window-for-recent-epochs-forward-secrecy-trade-off). |

## Rules for all modes

### Acceptance

An incoming object is accepted when all of these are true:

1. It authenticates: signature, application namespace, AAD and SFrame tag.
2. Its epoch is in the local receive window. A **future** epoch fails with
   `object epoch ahead`; the object is not recorded, so it can be received
   again after this node catches up. An evicted epoch fails with
   `object epoch expired`.
3. Its author is in the current roster at the same leaf with the same key. The
   objects of a removed member are refused, also objects from before the
   removal that were still in flight.
4. It is new: see [duplicates](#duplicates).
5. It fits the [pending bounds](#pending-bounds).

### At least once

- An accepted object becomes **pending**. The inbox stores it as
  authenticated plaintext, so it does not need the epoch key again.
- `poll_pending_object` returns the next pending object without removing it.
  It returns the same object again until the application resolves it.
- `stage_object_acknowledgement` (application accepted it) and
  `stage_object_rejection` (application refuses it for good) remove it. Save
  the candidate, then adopt it. A crash before the save offers the object
  again after restart.
- The application must be idempotent on (member, publication id): a crash
  between the application's own commit and the saved acknowledgement delivers
  the object again. Exactly once is not claimed.

### Duplicates

- **Replay window** per (author, epoch): a floor plus up to
  `REPLAY_ENTRIES` = 1,024 accepted counters above it. Counters at or below
  the floor are closed. A late object inside the window (for example one
  that recovery brings) fills its gap and is accepted.
- When the window is full, the floor moves up to the oldest entry. Counters
  below it that were never seen are given up as lost: such an object is
  refused as outside the window. It is never delivered twice.
- Acknowledging or rejecting an object does not reopen its counter.
- **Publication id ring**: the last `RECENT_IDS` = 256 accepted
  (author, id) pairs, across epochs. A publication that the author
  re-publishes under a new epoch or counter (ADR A2 step 10) is a duplicate.
- Replay windows for epochs that leave the receive window are deleted. Those
  objects can no longer decrypt, so they cannot be accepted again.

### Pending bounds

Bytes are encoded bytes: payload plus metadata (topic, recipients, current
value data). An author is charged for its own metadata too.

| Bound | Value |
| --- | --- |
| Pending bytes per author | 32 KiB (`MAX_PENDING_BYTES_PER_AUTHOR`) |
| Pending objects per author | 128 (`MAX_PENDING_OBJECTS_PER_AUTHOR`) |
| Pending bytes, all authors | 96 KiB (`MAX_PENDING_BYTES`) |
| Pending objects, all authors | 512 |

An object over a bound is refused (`author pending quota exhausted` or
`pending inbox full`) and is **not recorded**. It can come again, live or by
recovery, after the application drains work. One author cannot use up the
space of the others. The bounds apply to recovered objects too: recovery is
not exempt. Automatic recovery stops at the bound and continues later (see
[prefix admission](#group-mode)). One exception: a direct object that fills
a gap which holds back all of an author's pending objects may go over the
author quota by that one object (see [direct mode](#direct-mode)).

### Scheduling

- `pending_excluding` serves the eligible scope that was served longest ago
  first (round robin). Ties go to the earliest arrival. One busy author cannot
  starve the others.
- Inside a scope, the object with the lowest (epoch, counter) goes first.
- The application can defer scopes for one call. A deferred scope keeps its
  order; nothing overtakes inside it.

### Epoch changes

A membership step (admission, management, invitation control, removal of
another member) is never refused because of pending work. The runtime stages
the delivery state with the new epoch (`carry_delivery`):

| State | After the step |
| --- | --- |
| Pending objects | Kept, all of them. |
| Replay windows, recovery progress, retained ranges | Kept for epochs in the new receive window. |
| Direct recovery copies | Kept while their object epoch is in the window. |
| Publisher logs | One log per epoch in the window, keyed by (epoch, fingerprint). |
| Current index, retained current views | Cleared. Current values are per epoch; authorities publish again. |

When the **local** member is removed, the session ends with a removal record.
Its pending objects are not delivered.

### Time

- Every expiry is `UnixSeconds`: whole seconds since the Unix epoch (UTC).
- An expiry set by another member's clock (current values, retained current
  views) passes only `EXPIRY_SKEW_SECONDS` = 120 s after its value.
- An expiry set by this node (its own current index, `retain_until`) is exact.

### Storage

- One workspace attachment holds the publisher log and the inbox. Each has a
  fixed budget: `PUBLISHER_BUDGET` = 192 KiB and `INBOX_BUDGET` (the rest).
- Saving never evicts either part to make room for the other. The operation
  that would grow the inbox past its budget fails instead.
- The inbox is a canonical binary snapshot (`DFIC` v5). Payloads are raw
  bytes.

## Group mode

Group objects go to every subscriber of the topic.

- **Sequence.** Each group object has the author's publisher sequence for its
  epoch. The sequence is in the AAD.
- **Retention.** The author keeps a log per epoch in the receive window: at
  most 32 records per topic, inside `PUBLISHER_BUDGET` for all epochs. Older
  epochs and records give way first. An evicted range leaves a watermark and
  is reported as unavailable, never as complete.
- **Who may recover.** A requester gets epoch E history only when it is a
  current member, the current policy lets it read the topics, and it was
  already a member in epoch E. A removed member gets nothing. A member admitted
  after E gets nothing from E.
- **Recovery.** Ranges are signed by the author for (workspace, author, epoch,
  topic selection, after, through). Automatic recovery progress is per
  (author, epoch, selection). A holder may keep an exact author-signed range
  (`retain_until`) and serve only that range.
- **Prefix admission (B7b).** A served range can be up to
  `MAX_REPLY_BYTES` = 128 KiB, but one author may hold only 32 KiB pending.
  The requester verifies the **whole** signed range first. Then automatic
  recovery (`stage_recovery_range`) admits records in order until the first
  record that the pending bounds refuse. It stops there. Progress moves only
  to the sequence of the last record admitted (or found duplicate); the
  candidate reports it as `accepted_through`. The refused record and the
  records after it are not recorded, so a later request after the
  application drains brings them again. Because the signature covers the
  whole range, the records at or below that sequence are exactly the
  complete prefix. When no record fits, the state is
  `recovery_awaiting_application`: no candidate, no progress. Drain, then
  request again. An explicit range (with `after` from the caller) stays all-or-nothing
  and fails at the bound. `through` can be omitted to ask a holder for its
  bounded available tail. Such a range never advances full-history progress
  across the omitted prefix, even when Core selects the holder automatically.
  Cost: in the worst case, each cycle fetches up to 128 KiB again to admit
  about two full-size objects. The wire format did not change.
- **Epochs (A3f).** Authors and holders serve, and receivers verify, ranges
  for any epoch in the receive window (`arachne-delivery` API). The runtime
  recovery operations (`fetch_recovery_range`, `discover_recovery_cutoff`)
  take an optional `epoch` in the receive window; without it they ask for the
  current epoch. An epoch outside the window fails with `EpochMismatch`
  (600). Test: `arachne-runtime/tests/recovery_epoch_window.rs`.
- **Ordering.** No order between authors. Objects of one scope come in author
  order when they are pending together; a late object can come after newer
  ones that were already delivered.
- **Loss.** Live transport is best effort. Recovery closes gaps inside
  retention.

## Direct mode

Direct objects go to an explicit, sorted list of recipient members.

- **Sequence.** Each recipient scope has its own sequence. It continues across
  epochs. The recipients are in the AAD.
- **Ordering.** Inside a scope, an object waits while an earlier sequence is
  missing. It is released when recovery fills the gap or when the gap is
  recorded as missed. A gap is recorded as missed in two ways, and both
  report `missing_count`:
  - every source has failed (`stage_direct_miss`);
  - the receiver's recovery copies overflow (32 records per scope or 32 KiB)
    and eviction moves the scope floor past the gap (B7e). The staging step
    that evicts (`poll_protected`, `stage_recovery_range`,
    `stage_direct_recovery`) reports the given-up sequences as
    `missing_count` on its candidate.
- **Late objects.** A direct sequence at or below its scope floor was either
  accepted or recorded as missed. A late copy of it is dropped as a
  duplicate. It is never delivered after newer objects of the scope.
- **Retention.** Senders and recipients keep recovery copies: at most 32
  records per scope and 32 KiB in total; the largest scope gives way first.
  Only members of the audience can ask for them.
- **Heads.** A head tells an audience member how far a scope goes. It only
  starts gap recovery; it proves nothing about content.
- **Recovery under the quota (B7c).** A direct range is verified whole, then
  admitted as its in-order prefix up to the first record that the pending
  bounds refuse. The records not admitted are not recorded, so the scope
  keeps its gap from there and `next_direct_gap` asks for them again. When
  no record fits, `stage_direct_recovery` returns
  `direct_recovery_awaiting_application` and stages nothing.
- **Gap that holds back everything.** When every pending object of an author
  waits behind a direct gap, the application cannot acknowledge any of them.
  The object that is the next missing sequence of its scope is then admitted
  even over the author quota, from recovery or live. It is deliverable, so the
  next object of that author meets the quota again: an author goes over its
  quota by one object at most. The all-authors bound still applies. It
  cannot hold back a gap filler for good (B7d): an object waits behind a gap
  only while the receiver keeps the records above that gap, at most 32 KiB
  and 32 records per scope. When a record is evicted, the scope floor moves
  past the gap, the gap is recorded as missed, and the objects above it become
  deliverable. So gap-blocked
  objects stay far below 96 KiB and 512 objects, and the application can
  always drain work.

## Current mode

Current values are latest values: one per (authority, policy revision,
topic, selector, replacement key).

- A newer value replaces the older one; a tombstone deletes it. Values expire
  at `expires_at`.
- An authority serves an exact signed view of its current values for the
  current epoch only. A holder may retain a view while one value in it is
  fresh.
- A receiver does not deliver values that expired, allowing clock skew. It
  counts them as stale.
- On an epoch change current views start empty. Received current values that
  are pending stay pending.

## Not guaranteed

- Exactly-once delivery to the application.
- A total order, or causal order between authors.
- Delivery to a peer that stays offline longer than retention, or more than
  `RECEIVE_EPOCHS` epochs behind.
- Delivery of objects from a member removed before they arrived.
- Confidentiality between applications in one workspace. See
  [security](security.md#application-namespaces-domain-separation-not-isolation).

## Tests that check this contract

| Rule | Test |
| --- | --- |
| Receive window, removed author, future epoch, new member | `arachne-security` `object::recent_epochs_stay_readable_for_receive_only_then_expire`, `object::objects_are_independent_authenticated_and_epoch_scoped` |
| Namespace binding | `object::objects_are_bound_to_their_application_namespace` |
| Partitioned peers at different epochs; who may recover; removal | `arachne-delivery/tests/epochs.rs` `members_at_different_epochs_exchange_data_after_a_partition_heals` |
| Round robin, gap fill, cross-epoch dedup | `epochs.rs` `fair_scheduling_gap_fill_and_cross_epoch_dedup` |
| Per-author quota, binary storage | `epochs.rs` `per_author_quota_and_binary_pending_storage` |
| Quota still refuses a flooding author's live traffic | `recovery_bound.rs` `flooding_author_still_hits_the_pending_quota_for_live_traffic` |
| Byte-bounded served range (B7) | `recovery_bound.rs` `automatic_recovery_serves_byte_bounded_prefix_and_continues` |
| Prefix progress stays inside the signed range | `recovery_bound.rs` `recovery_prefix_progress_is_bounded_by_the_signed_range` |
| Direct recovery prefix, gap that blocks all pending objects, direct flood | `direct_quota.rs` `direct_recovery_admits_the_prefix_that_fits_the_author_quota`, `a_gap_that_holds_back_all_pending_objects_can_always_be_filled`, `deliverable_direct_flood_still_hits_the_author_quota` |
| Eviction past a gap records a miss; late direct objects are dropped | `direct_eviction.rs` `eviction_past_a_gap_drops_the_late_object`, `a_late_object_below_an_explicit_miss_is_dropped`; `arachne-runtime/tests/direct_eviction_miss.rs` `evicting_past_a_direct_gap_reports_the_miss_and_keeps_order` |
| All-authors bound never stalls gap-blocked direct objects (3 authors) | `direct_global_bound.rs` `gap_blocked_objects_of_three_authors_never_stall_the_global_bound` |
| Automatic recovery progresses under the author quota (runtime) | `arachne-runtime/tests/recovery_quota.rs` `automatic_recovery_of_large_objects_progresses_under_author_quota`, `automatic_recovery_waits_for_the_application_when_the_quota_is_full` |
| Save never shrinks publisher history | `epochs.rs` `publisher_history_never_shrinks_to_make_room_for_inbox_state` |
| Replay window bound, restart, acknowledgement | `inbox::durable_pending_objects_and_bounded_topic_replay` |
| Deferred scopes | `inbox::deferred_streams_preserve_order_identity_and_restart` |
| Clock skew on remote expiry | `current::tests::latest_value_index_coalesces_isolates_and_expires`, `inbox::current_value_survives_authenticated_delivery_bundle` |
| Membership step with pending objects (runtime) | `arachne-runtime` `tests::removal_is_not_delayed_by_pending_objects_and_delivery_state_carries`, `tests::pending_object_query_bounds_and_gap_epoch_guard` |
