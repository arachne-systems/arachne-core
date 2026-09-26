# Receive counters for the restart diagnosis

BLUF: Three cumulative counters show where a stream stops making progress. They
add no timeout, retry, peer-readiness promise, or delivery acknowledgement.

- `groups_received`: recv_group returned a group.
- `frames_received`: the first read_frame returned a frame.
- `groups_completed`: the second read_frame confirmed the expected clean end.
- Existing `packets_received`: envelope validation and local admission succeeded.

The counters are AtomicU64 values with relaxed ordering. MoqMetrics keeps its
Copy and Serialize derives. The existing runtime JSON method forwards the new
fields. No SDK wrapper or payload-specific type is added. Values are cumulative
across peers, so compare their changes while the other peer is idle. A snapshot
can observe an in-progress increment; a persistent difference identifies a step.

## Checks

The existing real MoQ delivery test first failed to compile for the three absent
fields (`/tmp/moq-receive-counters-red.log`). With the fields and increments added,
all four moq_stream integration tests passed in 3.15 s. They include outsider
rejection, recent-prefix delivery, a three-peer critical reply, and restart.
The extended moq_restart binary passed three tests, with one subprocess helper
ignored, in 19.14 s. Runtime check with the moq feature passed in 26.03 s.
Receipts: `/tmp/moq-receive-counters-{green,restarts-green,runtime-check}.log`.
`git diff --check` passed. No device test was run by this lane.

These checks validate the counters and preserve the existing transport behavior.
They do not reproduce or fix the observed Android receive stall.
