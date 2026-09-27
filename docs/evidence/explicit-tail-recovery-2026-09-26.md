# Explicit retained-tail recovery

## BLUF

A caller can recover after a known authenticated sequence without requesting evicted earlier history. The range stays bounded and verified. It does not advance full-history recovery progress. This is recent-tail repair, not an archive.

## Change

`RecoveryRangeRequest { after: Some(cursor), through: None }` asks an authorized holder for the available tail. An explicit cursor does not claim omitted history. Default recovery still starts from durable accepted progress. Existing already-covered and author, workspace, epoch, holder and proof checks remain.

## Evidence

- RED: `explicit_tail_recovery_does_not_claim_evicted_history` rejected the explicit open tail as an invalid range. `/tmp/core-tail-recovery-red.log`.
- GREEN: the third-holder recovery binary passed all 5 tests in 14.34 seconds with MoQ enabled. `/tmp/core-tail-third-holder-final.log`. The new case publishes 40 objects, recovers after sequence 39, and proves default full-history recovery still reports unavailable.
- Runtime test build: `cargo +1.98.0 test -p arachne-runtime --features moq --no-run --message-format=json`, green. `/tmp/core-tail-runtime-build.json` and `.log`.
- The old mobile branch full-runtime run found an existing Internal error-count failure: 91 sites, ceiling 89. Two infallible JSON projections (MoQ primitive counters and optional presence fields) now build their values directly. The ceiling stays 89. The focused ratchet passes: `/tmp/core-tail-ratchet-green.log`.
- The full mobile runtime run is still in progress. Its original receipt is `/tmp/core-tail-runtime-suite.json`; do not treat its original ratchet RED as a clean run. The typed integration branch receives the recovery change and keeps its typed projections.

## Device limit

The prior APK reproduced a missing End after a receiver restart, then returned `History(Unavailable)`. `/tmp/ptt-missing-end-red.json`. This commit has not yet passed that device check. The SDK must derive a contiguous recording cursor and the app must pass it to this general API. Saved Blobs and a durable catalog remain separate work.

## Typed integration check

The integration merge keeps H4 typed stream metrics and H2 record candidates. The new fixture uses the existing in-memory record provider and candidate tokens. The first merge check caught old fixture calls (`create` and `snapshot`); those calls were updated. All 5 third-holder tests then passed in 11.06 seconds with all features. `/tmp/core-tail-integration-tests.log`.

The storage-compatible mobile APK now passes the missing-End fault check: stop the receiver before End, wait beyond MoQ's five-second window, restart it, then recover through Core. Completion took 1.087 seconds. `/tmp/ptt-missing-end-tail-check.json`. This proves recent retained recovery from the author, not archive transfer or an offline-author holder on tablets.
