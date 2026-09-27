# Adversarial test matrix

This matrix is the release receipt for network faults and resource exhaustion.
Run it from a commit that contains the five P0 hardening branches tracked by
`ptt-60z.4.1` through `.4.5` and the transport regression fix `ptt-yff.8`.
Record the exact commit, command, pass/fail/ignored counts, and any minimized
regression added after a failure.

Every Cargo command on the shared machine uses:

```text
flock /home/user/development/worktrees/.cargo-build.lock nice -n 10 \
  env CARGO_BUILD_JOBS=4 cargo ...
```

## Deterministic matrix

| Fault | Reproduction and invariant | Expected availability limit |
| --- | --- | --- |
| Loss, gap, and recovery | `cargo test --locked -p arachne-delivery --test direct_eviction --test recovery_bound --test direct_quota` proves explicit misses, bounded recovery prefixes, and author quotas | History outside the signed retention window is unavailable |
| Duplication and replay | `cargo run --locked -p arachne-runtime --features test-fixtures --example real-iroh-qualification -- --endpoints 3 --scenario duplicate --deadline-seconds 120 --receipt /tmp/arachne-adversarial-duplicate.json` plus `cargo test --locked -p arachne-security application_authentication_replay_and_restart` | Duplicate delivery is allowed; duplicate state transitions are rejected or idempotent |
| Reordering and late data | `cargo test --locked -p arachne-delivery --test direct_eviction --test epochs` proves late objects and epoch-window behavior | Objects below an explicit miss or evicted retention boundary stay unavailable |
| Delay and caller timeout | `cargo test --locked -p arachne-node --test connection_reuse late_reply_after_caller_timeout_does_not_poison_reused_connection` and `cargo test --locked -p arachne-runtime --test lifecycle` | The operation may fail or become uncertain at its deadline; later operations must remain usable |
| Partition and healing | `cargo run --locked -p arachne-runtime --features test-fixtures --example real-iroh-qualification -- --endpoints 1 --scenario partition --deadline-seconds 120 --receipt /tmp/arachne-adversarial-partition.json` and `cargo test --locked -p arachne-delivery --test epochs members_at_different_epochs_exchange_data_after_a_partition_heals` | No availability during a full partition; safety and convergence resume after a valid path returns |
| Simultaneous dial and churn | `cargo test --locked -p arachne-node --lib` and `cargo test --locked -p arachne-node --test connection_reuse --test moq_restart` | A peer restart interrupts in-flight work; bounded retry and recovery may be required |
| Stale addresses | `cargo test --locked -p arachne-runtime membership_peer_choice_skips_recent_failures_until_nothing_else_is_left` and the restart scenario below | All stale hints can delay connection until the operation deadline; they grant no authority |
| Restart recovery | `cargo run --locked -p arachne-runtime --features test-fixtures --example real-iroh-qualification -- --endpoints 1 --scenario restart --deadline-seconds 120 --receipt /tmp/arachne-adversarial-restart.json` plus `cargo test --locked -p arachne-runtime --features test-fixtures --test native_persistence --test removed_membership` | Only durably adopted state survives; uncertain candidates require explicit recovery |
| Relay failure | `cargo run --locked -p arachne-runtime --features test-fixtures --example real-iroh-qualification -- --endpoints 1 --profile relay --relay-infrastructure local --scenario relay-loss --deadline-seconds 120 --receipt /tmp/arachne-adversarial-relay-loss.json` | Relay-only peers are unavailable while the configured relay is down; no direct fallback is claimed |
| Tor failure and slow peers | `cargo test --locked -p arachne-iroh-tor-transport` after `.4.3` through `.4.5`; live Tor evidence is separately required by `ptt-60z.7.1` | Tor-only peers are unavailable with the daemon/network down; framing timeout releases capacity |
| Disk/write failure | `cargo test --locked -p arachne-store` injects a second-write failure, rejects oversized records, reopens, and checks encrypted journal state | A failed durable adoption remains unapplied or uncertain; disk capacity itself is host-operated |
| Queue saturation | `cargo run --locked -p arachne-runtime --features test-fixtures --example real-iroh-qualification -- --endpoints 2 --scenario queue-pressure --deadline-seconds 120 --receipt /tmp/arachne-adversarial-queue.json`; node library tests cover control and replay queues | Best-effort traffic may drop; critical/current delivery must remain retryable without unbounded memory |
| Oversized input | Store, membership-wire, node-stream, gossip-cache, and Tor frame tests reject before unbounded allocation | The offending input is dropped; its connection may close |
| Malicious/slow peer | `cargo test --locked -p arachne-node --test live_pubsub` covers stalled data connections, stranger control quotas, and uncertain sends; Tor tests bound unauthenticated streams | Capacity is finite. Authenticated useful traffic retains reserved space but cannot guarantee availability under host-wide exhaustion |

## Receipt rules

1. A failure gets a deterministic minimized regression in the owning crate.
2. A rerun does not erase the first result; record both and explain the change.
3. RSS, queue bytes, open sockets, and elapsed deadlines are measured for scale
   or live runs. Unit tests prove logical ceilings, not process-wide memory use.
4. Public relay and live Tor behavior are separate evidence. Local fake streams
   do not satisfy `ptt-60z.7.1`.

## Remaining environment qualifications

The local deterministic matrix does not emulate arbitrary packet loss,
reordering, bandwidth, and latency below Iroh. The vendored Iroh Patchbay tests
contain link outage, relay restart, UDP-blocked, and slow-3G scenarios, but they
require their network namespace/container environment. Run those tests, or an
equivalent pinned `tc netem` lab, before claiming measured behavior under link
degradation. Track that receipt separately so lack of host privileges cannot be
mistaken for a passing product result.

## 2026-09-27 execution snapshot

The logical store/delivery slice passed 39 tests with zero failures. Against the
ready transport regression fix `462755f`, the real-Iroh duplicate scenario
passed with four endpoints in 1,172 ms, and queue pressure passed with three
endpoints, peak admission queue depth 1, in 179 ms. Receipts were written to the
`/tmp/arachne-adversarial-*.json` paths above.

Two harness failures were minimized and tracked instead of being rerun away:

- `ptt-60z.4.6`: partition restore fails because the harness omits the required
  freshness anchor.
- `ptt-60z.4.7`: restart panics by nesting a Tokio `block_on` call.

The matrix remains a release blocker until those regressions, the five P0
hardening branches, the transport regression fix, and the live qualifications
are integrated and green together.
