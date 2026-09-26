# Streaming restart check, 2026-09-26

**BLUF:** A real process kill and restart now restores a protected round trip in less than three seconds. All 79 Node tests passed; 4 checks were ignored. This is local transport evidence. Tablet proof is separate.

## Cause and changes

1. Either authorized peer can start a MoQ connection. A route starts work in the background. A new incoming session can replace an old receive subscription before its QUIC timeout.
2. Iroh 1.2.0 routed new QUIC Initial packets only to its selected path. That path can still point to a stopped process even after a fresh peer address arrives. The local Iroh patch uses its existing known-address fanout for Initial packets. Established traffic retains Iroh path selection.
3. A fresh MoQ session refreshes data-connection cache ownership before it announces its subscription. Existing exchanges keep their handles. A late failure discards only its failed handle and cannot evict a replacement connection.
4. Active session counts start only after the receive track is subscribed. Temporary diagnostic fields and probes were removed.

## RED evidence

- `/tmp/core-moq-restart-red.log`: the one-sided dial policy waited for the old session after a process kill.
- `/tmp/core-moq-specific-discard-moq_restart.log`: either peer could connect, but the protected return packet still failed the three-second limit with unmodified Iroh.
- `/tmp/core-moq-refresh-arachne_node.log`: a late failure on a discarded handle closed the new cached connection.

## GREEN evidence

Build command: `CARGO_BUILD_JOBS=4 CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 cargo +1.98.0 test -p arachne-node --features moq --no-run --message-format=json`, under the shared build lock.

The 18 generated test binaries ran on CPUs 24–27 with `--test-threads=4`: **79 passed, 0 failed, 4 ignored**. The ignored checks are the subprocess helper and explicit measurement utilities. Tor is not enabled in this check. See [per-binary receipt](moq-restart-2026-09-26.json).

The process-kill test passed three initial runs in 0.294–0.307 seconds and the full-suite run in 0.29 seconds. The connection reuse suite passed 6/6, including cancellation and overlapping exchanges. The mDNS refresh test passed. MoQ burst and graceful restart tests passed 3/3.

## Consumer requirement

The Core, SDK, and native application Cargo roots must all select `vendor/iroh`. Cargo does not inherit dependency-owned patch tables. See [Iroh provenance and exact source change](../../vendor/iroh/ARACHNE-PATCH.md). No storage format changed in this patch.
