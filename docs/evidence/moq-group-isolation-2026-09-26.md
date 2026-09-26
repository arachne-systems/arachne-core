# Bounded independent MoQ group reads

BLUF: A partial payload or missing group end cannot block later complete groups.
The receiver has at most eight group readers. Each reader uses the existing
five-second live replay window. Session close cancels all reads. This fixes a
separate host defect; it does not prove a fix for the current tablet stall.

## Scope and ordering

The receive loop owns one `FuturesUnordered` set. It starts no detached task.
When all eight slots are full, it stops taking more groups until one read ends.
A stalled reader expires at `track::DEFAULT_MAX_AGE` (five seconds). An expired
or malformed group ends the session and drops the other readers.

Each reader checks the first frame header against the existing 128 KiB frame
limit before it assembles the payload. Eight readers can hold at most 1 MiB of
validated-size envelopes. This bound does not include the upstream MoQ track
cache. A second frame is rejected from its header. An empty group, invalid
envelope, or wrong group sequence is also rejected. The existing scope, topic,
operation, and authenticated routing checks run before delivery.

Complete independent groups are applied in completion order. A later group can
arrive before an earlier group whose body or EOF is still missing. If the earlier
group completes before its reader deadline, it is delivered too. The transport
does not promise sequence order across independent groups. Consumers must use
the publication sequence and their existing content rules where order matters.

The group deadline is the existing live replay window, not a reconnect timeout.
The session close future is polled during the group wait and during all pending
header, body, and EOF reads. Dropping the receive loop drops its readers.

## RED evidence

The two tests first ran on the unchanged receive loop and failed because a later
complete group did not arrive within one second. The partial-body case had
counters `1/0/0/0`; the missing-EOF case had `1/1/0/0` for groups, frames,
completed groups, and delivered packets.

- H1 original receipt: `/tmp/moq-unfinished-group-red.log` (0 passed, 2 failed).
- H7 repeat: `/tmp/moq-group-isolation-red.log` (0 passed, 2 failed; 3.01 s).
- RED commit: `e291be4`, from H1 commit `49e8eef`.
- Production-only fix: `ad456026d871803e0f9522701cfff2b0897f0b1c`.

## Focused GREEN evidence

The two original tests passed with the production change before test expansion:
`/tmp/moq-group-isolation-prod-tests.log` (2 passed, 0 failed; 3.01 s).

The expanded unit checks passed 7/7 in 6.02 s:
`/tmp/moq-group-isolation-controls-final-tests.log`.

| Check | Result |
| --- | --- |
| Partial payload, then 16 complete groups | All 16 arrive; late earlier group also arrives |
| Missing EOF, then 16 complete groups | All 16 arrive; late earlier group also arrives |
| Close during partial payload | Active receive session exits within one second |
| Close while EOF is missing | Active receive session exits within one second |
| Oversized header with no body | Rejected without waiting for payload |
| Empty, invalid, extra-frame, wrong-sequence group | Rejected |
| Eight stalled readers | Each expires at the five-second live window |

The first expanded run passed 6/7. Its late partial-body fixture dropped the
frame producer without calling `finish()`. Upstream MoQ correctly returned
`Dropped`. The corrected fixture explicitly finishes that frame. No production
change was needed for that test correction. The original receipt remains at
`/tmp/moq-group-isolation-controls-tests.log`.

The existing stream integration tests passed 4/4 in 3.05 s, including the
unauthorized outsider case, three-peer critical reply, late interest, and same
port restart. Receipt: `/tmp/moq-group-isolation-stream-tests.log`.

The restart integration binary passed 3/3 with one subprocess helper ignored
in 18.37 s. It covers unannounced restart plus 12 three-peer burst restarts and
12 paced restarts. Receipt: `/tmp/moq-group-isolation-restart-tests.log`.

## Build and evidence limits

The test build used Rust 1.98.0, `--locked`, the shared Cargo build lock, four
build jobs, CPUs 4-7, no incremental state, and no debug data. The commands built
`arachne-node` with feature `moq`, its library tests, and the `moq_stream` and
`moq_restart` integration binaries. The binaries ran outside the build lock.

There is no API, storage, wire format, or dependency change. No tablet check ran
in this lane. The current hardware stall has equal receive phase counters; the
unfinished-group RED has a different counter pattern. The lead is investigating
that hardware stall separately. A full integrated suite follows the final Core
source freeze.
