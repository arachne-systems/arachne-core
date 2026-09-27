# Authenticated MoQ arrival and stale dial backoff

BLUF: A fresh MoQ connection that passes the existing route and topic checks
now clears that peer's old failed-dial schedule. The change records no network
address and changes no authority or retry interval. A real-Iroh test first
failed with the same cooldown error seen on the tablet, then passed with the
11-line production change. This does not close the separate live stream stall.

## Device observation

H1 found this sequence in `/tmp/ptt-moq-state-second-91.log`, PID 23050. This
lane read the listed events; it did not operate a tablet.

| Local time on 2026-09-26 | Observation |
| --- | --- |
| 08:05:44.407 | Incoming MoQ connection `12970367401944136832` is admitted. |
| 08:05:44.409 | The receive task selects that fresh connection. |
| 08:05:49.413 | Its separate data-ALPN interest announcement times out at connect. |
| 08:05:49.666 | An older selected MoQ session closes due to `peer recently unreachable; retrying later`. |
| 08:05:49.730 | Fresh incoming MoQ connection `12970367401943738576` is admitted. |
| 08:05:49.731 | The fresh connection is selected, then closes for the same stale cooldown. |

The incoming MoQ path returns before the direct-frame path calls
`remember_observed`. Thus the authenticated transport arrival did not clear the
per-peer dial failure. The next interest announcement failed without a dial.

## RED and small fix

RED test commit: `4916f3b`. It creates two real Nodes, installs the existing
workspace policy and enables the receiver's stream route. It seeds a two-minute
cooldown for that sender and an unrelated endpoint. A new authenticated incoming
MoQ connection arrives. The next normal data-ALPN connection still fails with
`peer recently unreachable; retrying later`. The one-second observation bound
fails. Receipt: `/tmp/moq-reachability-red.log` (0 passed, 1 failed; 1.01 s).

Production-only commit: `7c7c4ccc6e6bdff030c463e2f49aa78549d2bc46`.
It adds 11 lines in `connections.rs` and `streams.rs`:

- A private reachability hook removes only the admitted peer's cooldown.
- `Streams::accept_connection` calls it after its existing route and topic
  authorization checks and before it passes the fresh connection to MoQ.
- It does not record an IP address, change membership, skip authorization,
  change retry timing, or modify a data format.

The unchanged RED test passes in 0.01 s. The normal data ALPN connects, and the
unrelated endpoint retains its cooldown. Receipt:
`/tmp/moq-reachability-green.log`.

## Narrow GREEN gates

| Gate | Result | Receipt |
| --- | --- | --- |
| Node library with the production fix and original RED test | 50 passed, 0 failed, 1 ignored; 43.42 s | `/tmp/moq-reachability-node-tests.log` |
| Existing MoQ streams, including outsider rejection | 6 passed, 0 failed; 6.03 s | `/tmp/moq-reachability-stream-tests.log` |
| Existing restart cases | 4 passed, 0 failed, 2 helpers ignored; 18.38 s | `/tmp/moq-reachability-restart-tests.log` |
| Added rejected-route control | 1 passed; cooldown remains | `/tmp/moq-reachability-negative.log` |
| Positive and rejected-route repeats | 10 runs each, 20 passed, 0 failed | `/tmp/moq-reachability-repeat-receipt.json` |
| Node strict Clippy, all targets and features | Passed; 20.25 s | `/tmp/moq-reachability-clippy.log` |
| Workspace format and diff whitespace | Passed | `/tmp/moq-reachability-fmt.log` |

The node library includes the existing bounded-group, late-completion, malformed
frame and close-cancellation checks. The additional negative control admits the
peer's identity as a member but installs no stream route. Its MoQ attempt is
rejected and its cooldown remains. The positive test also proves that an
unrelated peer's cooldown stays intact. The repeated tests use the same bounds
and assertions; they add no sleep or retry allowance.

## Evidence limits

The 724/0/22 full H7 receipt remains tied to frozen Core `0d37ba9`. This later
change has separate narrow checks. There is no full-suite or device claim for
this follow-up. H1 also observed a live one-way stall after subscription was
already established; this reachability change does not explain that trace.
The isolated Android GSO experiment is outside this branch.

All builds use the shared Cargo lock, Rust 1.98.0, four jobs, CPUs 4-7, no
incremental cache and no debug data. Test binaries run outside the lock. The
warm H7 target is retained for the lead's next source decision.
