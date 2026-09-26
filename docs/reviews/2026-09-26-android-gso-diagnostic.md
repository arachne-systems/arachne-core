# Android GSO restart diagnostic

**BLUF:** The first Android GSO A/B run completed all 40 recordings. The
baseline completed 34 of 40. The GSO run had one late audio batch and thus 39
complete output-write receipts. The cause of the baseline transport failure
is not established. The second run completed all 40 recordings and all 40
output-write receipts. The root agent selected the Android setting for mobile
candidate `c4c3151`, with the separate authenticated-reachability fix. The
original baseline and diagnostic branches remain available for review.

## Source and receipts

The baseline APK has SHA-256
`d1840619f838c7d5e294b94033771feb7de7a9ba3147a890f2b8d881541c9cdf`.
Both tablets had these same APK bytes.

| Part | Commit |
| --- | --- |
| App | `0dd6c1a92d4f0ccff76a675521a1cfc31f57e554` |
| SDK | `acbc0065dd0a9b9409b8c7d01742725469cf7709` |
| Core | `65ee1450fa5c73b0c3d9e8f7740c19f5538fcbda` |
| MoQ trace overlay | `31db67573852999bf0621139d8e8b40d5ef35e37` |

The trace overlay adds logs only. The root agent saved its Cargo override and
lock file, then restored the production Cargo files. See
`/tmp/ptt-moq-state-diagnostic-provenance.json` and
`/tmp/ptt-moq-state-diagnostic-install.json`.

The first run had 19 of 20 complete recordings and 16 complete output-write
receipts. The second run had 34 of 40 complete recordings and 32 complete
output-write receipts. These are separate checks; output-write completion does
not prove audibility. Reports:

- `/tmp/ptt-moq-state-restart20.json`
- `/tmp/ptt-moq-state-restart40.json`
- `/tmp/ptt-moq-state-second-50.log`
- `/tmp/ptt-moq-state-second-91.log`
- `/tmp/ptt-moq-live-stall-29-analysis.json`

## Live failure in talks 29 and 30

Tablet `.50` restarted. Its new process was PID `19275`. Tablet `.91` kept PID
`24025` from 08:06:56 through 08:07:24 CDT. Thus the receiver was present during
this failure.

| Observation | Value |
| --- | --- |
| Source endpoint prefix | `fe9f7988` |
| Receiver endpoint prefix | `f127e98a` |
| Source MoQ connection | `12970367441627054800` |
| Source GroupServe session token | `12970367442165146560` |
| Receiver MoQ connection | `12970367401944132416` |
| Matching publisher hop | `3932779124219666951` |

The receiver selected the new session at 08:07:08.543 and established the
subscription at 08:07:08.570. It received groups `16731`, `16732`, and `16733`
at 08:07:08.581, .666, and .780. It received no later group before its next
process restart.

Before source time 08:07:24, the source had opened, written, and finished all
17 groups in the condensed receipt. Only groups `16731` and `16732` reached
`phase=done`, which follows the final acknowledgement. The other 15 stayed at
`phase=closed`, which follows the local FIN write. The source reported no
terminal GroupServe error or drop for that session in this interval.

The receiver's groups `14681` and `14694` reached the source on the same
selected MoQ connection while this failure continued. Reverse traffic thus
continued. This observation does not identify whether the forward failure is
in the QUIC implementation, UDP path, or another lower transport layer.

Tablet `.50` was about 0.835 seconds ahead of `.91`. Use group IDs and the
matching hop for correlation. Connection IDs and pointer session tokens have
only local meaning. A publisher hop identifies a stream incarnation; Core
membership and topic policy remain the authorization source.

## Other failures in the same run

An aggregate session count can include the third tablet `.79`. It does not
prove that the intended peer can receive. Several early failed talks started
with one aggregate session while the intended route was still being built.

A separate recovery defect is under test in the H2 lane. On `.91`, PID `23050`
accepted a fresh authenticated MoQ connection at 08:05:49.730. It closed that
session at .731 because the separate data-ALPN connection had put the peer in
a dial cooldown. `run_peer` waits for `announce_interest` on that data ALPN
before it starts the MoQ receive path. This is distinct from the live failure
above, which occurred after the subscription was established.

## Controlled GSO comparison

The existing Android x86_64 configuration already disables segmentation
offload. The diagnostic commit changes only that platform guard to cover all
Android targets. It uses the existing transport option and adds no protocol,
timeout, readiness delay, or authorization change.

The root agent used the same MoQ trace overlay and restart script for the
A/B runs. This lane does not operate the tablets. Do not claim that GSO is the
cause from these samples or from host tests.

Source check for the diagnostic commit: `git diff --check` passed. The root
agent owns the Android build and device evidence. The initial normal candidate was
`codex/night-media-reconnect` at `65ee145`; the later selected candidate is below.

## First GSO result

The GSO APK SHA-256 is
`4e3f2abcdada7ee8ca78b299ad409f9f8e987a06db551df4acd2fbcc2fa239fa`.
Its app commit is `15321f714f700236f3a5cc0f974aad84335e11f9`, SDK commit is
`ead1aee28065b36c699e3426268bc90dee7ba784`, and Core commit is `1be05e3`.
It has the same MoQ trace overlay `31db67573`. The app commit difference from
the baseline contains only report edits. Exact source and override receipts
are in `/tmp/ptt-gso-diagnostic-source/`.

`/tmp/ptt-gso-phase-restart40.json` has 40 of 40 complete recordings and 39 of
40 complete output-write receipts. The 21 aggregate readiness observations
were between 0.954 and 2.612 seconds. These observations do not establish an
intended-peer readiness guarantee. Neither tablet log has a MoQ session-close
or GroupServe terminal-error event during this run. The live one-way failure
was not seen in this sample.

Talk 27, transmission `1dc0d538752bc3ec574d84e6fc82f378`, explains the strict
output failure. It has 11 recorded batches, 10 queued batches, and 10 written
batches. At 08:17:04.163, receiver PID `26996` logged
`stored_without_live_output` for batch index `0`. The same receipt has:

- `next_playout=11`, `native_queue_batches=0`
- `recorded=true`, `complete=true`, `expected_batches=11`
- `queued=false`, `buffered=false`
- `playout_allowed=true`, `overlap=false`, `start_known=true`

Thus the first batch arrived after native playout had advanced through the
transmission. It was retained in the complete recording. It was not queued for
live output. This receipt does not show an AudioTrack rejection or a lost
output callback. Its source is `/tmp/ptt-gso-phase-91.log`; the playback lane
owns the follow-up.

## Repeat and selected mobile candidate

`/tmp/ptt-gso-phase-repeat40.json` completed with exit code 0. It records 40 of
40 complete recordings and 40 of 40 complete output-write receipts. All
aggregate readiness observations were below three seconds. Across both GSO
runs, the result is 80 of 80 complete recordings and 79 of 80 complete output
receipts. No live one-way stall was observed. This evidence supports the
selected setting; it does not prove a hardware or kernel cause.

The root agent selected the following candidate on `codex/night-mobile-recovery`:

- `da8c6c1`: production-only backport of H2's authenticated-reachability fix
  `7c7c4ccc`. It clears only the admitted peer's stale dial cooldown. It changes
  no address hint or authorization rule.
- `c4c315111a376ed17148664c07154b429613b7a0`: the Android no-GSO setting with a
  factual qualification comment. This commit is a separate source delta for
  integrated Core.

The focused host gates on `c4c3151` passed:

| Gate | Result | Receipt |
| --- | --- | --- |
| Node MoQ build | Passed | `/tmp/moq-final-mobile-build.log` |
| Stream, cache, gap, outsider and reconnect tests | 6 passed | `/tmp/moq-final-mobile-streams.log` |
| Duplicate session handoff tests | 2 passed | `/tmp/moq-final-mobile-handoff.log` |
| Process restart tests | 4 passed, 2 subprocess helpers ignored | `/tmp/moq-final-mobile-restart.log` |

The build used the shared Cargo lock, four jobs, toolchain 1.98.0, no incremental
cache, and no debug information. Test binaries ran outside the lock on CPUs
0-3. The host tests do not exercise the Android-specific transport option.
The root agent owns the final APK build and the longer device run on the
combined candidate. Those checks are not yet included in this note.
