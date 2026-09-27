# MoQ subscription prefix recovery

## BLUF

An enabled stream now keeps the protected publications sent before a peer's
interest announcement arrives. The receiver requests the publisher's recent
window with an explicit nonzero start. This preserves the opening publications
when the stream attaches late. Device and full-suite checks follow separately.

## Two causes in the shared transport

1. Protected publication selected only peers with an announced topic interest.
   An authorized, explicitly enabled MoQ route could exist before that interest.
   Publications in this interval never entered its recent track window.
2. Pinned MoQ Lite05 starts at the latest group when Group Start is absent.
   The five-second max-age setting alone does not request earlier groups.
   Its encoder also treats a start of zero as absent. A start of one preserves
   the bounded window; protected publication sequences are nonzero.

Broadcast selection now includes explicitly enabled routes for the same
workspace, revision and topic. Direct selection intersects these routes with
the validated endpoint audience. Each queue operation still rechecks current
authority, and the receiver checks its local subscription before admission.
Payload and direct-audience bounds apply before the MoQ path too. No new PTT
concept, protocol, dependency, storage format or authorization bypass is added.

## Regression and receipts

`enabled_stream_keeps_recent_publications_until_interest_arrives` configures a
sender route, sends three broadcast and three direct publications, and only then
subscribes and enables the receiver. It also checks payload and audience bounds.
All six payloads must arrive. The test has a twelve-second outer deadline.

- Initial RED: the prefix never entered MoQ. One test failed after 12.01 seconds
  in `/tmp/core-late-interest-red.log`.
- Queue-selection-only RED: six publications were queued, but only group six
  arrived. Trace: `/tmp/core-late-interest-trace.log`.
- Explicit zero-floor RED: the wire still selected only group six. Trace:
  `/tmp/core-late-interest-start-green.log` (the filename is historical; the
  result is RED).
- Explicit one-floor GREEN: all six arrived in 0.15 seconds. Trace:
  `/tmp/core-late-interest-floor-green.log`.
- Final source checks: `/tmp/core-late-interest-final-green.log` and
  `/tmp/core-late-interest-repeat.json`.

Build under the shared lock with `cargo +1.98.0 test -p arachne-node --features
moq --test moq_stream --no-run`. Run the resulting test binary with four assigned
CPUs, nice 19 and `--test-threads=1`. This also checks reconnect, three-peer reply,
and outsider/revision rejection.

## Evidence limit

This repairs recent stream startup. It does not create a recording archive.
The prior tablet check had 18/20 complete recordings; a new APK and device check
must prove that this transport change addresses those missing starts. No live
audio, archive replay or audibility result is inferred from this local test.
