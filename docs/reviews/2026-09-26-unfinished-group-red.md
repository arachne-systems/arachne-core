# Unfinished group reproduction — RED checkpoint

BLUF: An unfinished group blocks a later complete group at the Core receiver.
This is a separate defect. The tablet stall inspected on 2026-09-26 did not have
this counter pattern. No transport fix is included or proposed for that stall.

Two tests use real authorized Nodes. The public sender API always finishes a
group, so the fixture holds a wire producer open in its existing private route.
It then publishes a complete group through the normal Node API. There is no
handshake delay or transport mock. A receive-counter barrier proves that Core
has reached the unfinished group before the later publication.

Both tests failed because the later group did not arrive within one second:

| Held input | groups_received | frames_received | groups_completed | packets_received |
| --- | ---: | ---: | ---: | ---: |
| Partial first-frame payload | 1 | 0 | 0 | 0 |
| Complete first frame, missing group EOF | 1 | 1 | 0 | 0 |

Build: `cargo +1.98.0 test -p arachne-node --features moq --lib --no-run`.
Run the resulting arachne_node test binary with filter
`streams::tests::incomplete_group`, outside the build lock, on CPUs 0–3.
Receipt: `/tmp/moq-unfinished-group-red.log`; two failures in 3.05 s.
The build used the shared Cargo lock and no incremental or debug data.

The actual tablet failure, receiver PID 12105 in
`/tmp/ptt-group-diagnostic-91.log`, kept all four counters equal at 30.
It was waiting for another group. Do not use this RED to claim a tablet fix.
The parent requested this separate checkpoint while the connection investigation
continues. Its tests deliberately remain RED.
