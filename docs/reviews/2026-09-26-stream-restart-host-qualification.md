# Stream restart host qualification

BLUF: The new host cases pass. They do not reproduce the tablet receive stall. No production selection, timeout, or readiness rule changes in this checkpoint.

## Cases

- A forced second MoQ connection uses the same live publisher origin. The receiver accepts the cached first group on the replacement, then accepts all 13 later groups. Both a single-thread runtime and a four-worker runtime pass.
- A restarted process can publish 13 packets before it receives a packet from either survivor. Both survivors receive all packets during 12 process restarts. The sender uses two workers; the parent uses four. Each packet has a 2 KiB payload. Packet spacing is 75 ms. The delivery bound is three seconds for each restart.
- Publication sequences 13236 through 13247, then 13249 through 13251, all arrive. The absent sequence 13248 does not stop delivery.
- The same high sequence prefix can be cached before the receiver enables its route. All 15 groups, including the later groups after the gap, arrive.

## Evidence

- Same-origin handoff: first pass plus 20 unchanged single-thread repeats. `/tmp/moq-duplicate-handoff.log` and `/tmp/moq-duplicate-handoff-repeats/`.
- Parallel handoff: the two-test binary passes; ten further parallel repeats pass. `/tmp/moq-parallel-handoff.log` and `/tmp/moq-parallel-repeats/handoff-*.log`.
- Proactive process restart: initial pass and five unchanged repeats before the runtime change. The final parallel process case passes three times, with 12 restarts per run. `/tmp/moq-parallel-proactive.log` and `/tmp/moq-parallel-repeats/proactive-*.log`.
- Sequence gap: one pass in 0.06 s. `/tmp/moq-sequence-gap-red.log` has a GREEN result despite its file name.
- Cached prefix and gap: one pass in 0.05 s. `/tmp/moq-cached-gap.log`.

These are qualification cases. They did not produce a RED result and do not establish a defect fix. The separate unfinished-group RED and fix have their own record.

## Evidence limit

The fixtures use loopback Iroh and explicit address hints. They do not qualify Android scheduling, LAN loss, multicast discovery, or an exact destination readiness guarantee. On the tablets, restart checks still fail two of 20 transmissions. The sender and receiver traces match the destination and publisher hop. The receiver gets complete groups and then waits for the next group. More library trace evidence is required.
