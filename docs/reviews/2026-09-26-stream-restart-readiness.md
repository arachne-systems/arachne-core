# Stream readiness after restart

BLUF: The current PTT readiness flag does not prove delivery to the selected peer.
It counts receive subscriptions. The tablet failure still needs a transport cause.
Do not report the aggregate flag as a bidirectional reconnect receipt.

## Source and observation

The app source is `40533b01119677acdbc22e16f3b9d338bc92f5f4`. Its SDK is
`657e41cc687a5ef291c8ecfdd1e3229e85e0cf6e`; its Core is
`ddb3f697df24c8ef2dc4612cd7c126e865329866`.
The review used these local sources, the pinned Iroh MoQ `bd5afc4`, and MoQ
`6ab7d1a`. It did not change or check a tablet.

In `/tmp/ptt-combined-final-restart20.json`, 18 of 20 talks completed and all
18 were written to AudioTrack. Talk 13, after the sender restarted, left the
receiver with Start but zero audio batches and no End. Its transmission ID is
`1ded1ad340424f31ebf5af9670a82ebb`. Talk 14 then timed out on the floor grant.
Both tablets reported ready with two sessions after the failure. The later
parent-owned diagnostic logs show receiver packets_received at 3 for 17 s while
sender packets_sent reaches 66; receiver sessions_active and sessions_total both
stay at 2. These facts identify a receive stall. They do not identify its cause.
A later 500-talk attempt recovered without a manual restart: the two session
counts changed after about 46 s and 78 s. Its receipt is
`/tmp/ptt-stalled-500-{50,91}.log`. It did not meet the restart time bound.

## What each signal means

| Signal | Source | Meaning and limit |
| --- | --- | --- |
| sessions_active | Core `streams::receive_session` and `ActiveSession` | Number of local receive futures after subscribe succeeds. Decreases when a future drops. Has no peer, scope, age, or transmit receipt. |
| moqReady | JNI `configure_moq`, Kotlin `PttSession` | True if at least one receive subscription exists. It can clear a delivery error when a different route works. |
| wait_ready | App `scripts/ptt_rpc.py` | Requires sessions_active >= selected ADB tablets minus one. An unrelated third member can satisfy this count. |
| packets_sent and queued | Core `streams::publish_selected` | The local MoQ track accepted the group. Does not prove that a remote subscriber received it. |
| admitted | Core `publish_selected`, JNI `publication_receipt` | Can include local loopback. A nonempty list does not prove admission by the intended remote peer. |

The SDK forwards the Core counters. The new typed StreamMetrics has the same
limit. It correctly documents that queued data is not a remote receipt.

## Connection and cache findings

`run_peer` replaces its receive future for each different incoming connection.
It drops the old subscription before the new interest announcement and subscribe
finish. The Iroh MoQ actor retains duplicate connections and can return the oldest
open connection to connect(). A dead process can therefore leave an apparently
open session until QUIC detects closure. These are paths to test, not proven causes.

The protected publisher head is stored in the durable inbox record and restored
before workspace publication. Stream paths include the membership revision.
There is no source evidence that a normal durable restart resets its sequence.
Each stream keeps a five-second recent prefix. Core already requests start group 1
to avoid Lite05 treating start 0 as an omitted start. There is no missing-prefix
fix proposed by this review.

## Qualification seam

Use the public Node stream API in `crates/arachne-node/tests/moq_restart.rs`.
The new fixture keeps a third member connected, kills and restarts the same peer
identity on a new port 12 times, and sends 13 groups immediately after the app's
aggregate readiness condition. Both survivors must receive all exact echoes from
the restarted peer within 3 s. No settling delay is allowed. The child retains its
sequence range across restarts. A second variant uses 2 KiB payloads at a 75 ms
cadence to exercise changes while a transmission is in progress.

The first immediate-burst fixture used two-byte markers. Its first run and ten
repeats passed all 132 restarts (`/tmp/moq-three-restart-red.log` and
`/tmp/moq-three-restart-repeats/`). No RED was observed in this fixture. With
2 KiB payloads, the immediate and paced variants both passed, before and after
the receive-counter diagnostic. The final full binary passed three tests, with
one subprocess helper ignored, in 19.14 s. Each restart retains the 3 s bound.
Receipts: `/tmp/moq-three-restart-paced.log` and
`/tmp/moq-receive-counters-restarts-green.log`.

A green local result is not a tablet fix. The diagnostic commit adds cumulative
group, first-frame, and group-end counters to distinguish receive waits. If those
counters show a frame or group-end wait, use a deliberately unfinished group
followed by a complete independent group as the next deterministic test. Core
currently reads each group to completion before it asks for the next group.
Per-peer connection and sequence data can then separate replacement from loss.
No transport behavior change is included in this checkpoint.
