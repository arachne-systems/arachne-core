# Mobile and generated SDK boundary review

Date: 2026-09-27

Reviewed trunks:

- Core `integrate/wave1` at `005bc6f`
- generated SDK `feat/uniffi-sdk` at `4a2ac72`, Core pin `f7d78b0`
- ATAK plugin `main` at `5c5c3e1`
- PTT app `master` at `bcb59c1`

## Result

The generated ABI delegates protocol validation and lifecycle ownership to Core.
Its foreign object guards prevent use after free, and the SDK smoke checks now
exercise Kotlin handle destruction and redact `ClientConfig` secrets in all four
generated languages.

Android secrets are stored in app-private storage. PTT wraps its independent
endpoint and storage roots with an Android Keystore AES-256-GCM key, clears the
plaintext arrays after the native open call, and stores Core databases under
`noBackupFilesDir`. Both Android apps disable legacy backup, cloud backup, and
device transfer explicitly. ATAK's QR scanner is now internal rather than an
exported Activity. PTT release signing reads an external properties file and
stays unsigned when it is absent. ATAK's documented release path accepts only a
TPP-signed APK after certificate verification; locally debug-signed release
builds are build checks and must not be published.

One P0 release blocker remains: the plugin and PTT trunks do not implement the
same IPC protocol. ATAK `main` removed `PLUGIN_SESSION` and implements
`plugin-link-v2`; PTT `master` still exposes `PLUGIN_SESSION`. Any app can start
the exported PTT Activity with an attacker-controlled loopback server and ticket,
so the retired protocol cannot authenticate the ATAK host. Bead `ptt-60z.6.1`
tracks landing one matching, spoof-tested protocol on both trunks. A partial
implementation exists on PTT `feat/sources-combiner`, but it is coupled to that
branch and was not copied onto the designated trunk during this review.

## Boundary evidence

| Boundary | Evidence | Result |
| --- | --- | --- |
| Malformed and oversized input | Core record and protocol limit tests; `PluginWorkspaceClient` 256 KiB frame, 12 KiB publication, 32 pending send, and 64 queued publication limits; `PttLinkCheck` wrong protocol, workspace, expiry, and replay cases | bounded/fail closed |
| Cancellation and concurrent close/use | `arachne-runtime/tests/lifecycle.rs`; generated Kotlin and Swift close/wait smoke checks | covered |
| Foreign stale handles | UniFFI Kotlin atomic call counter/destroy guard; Kotlin smoke calls through a destroyed handle and repeats close | covered |
| Callback reentry | No application callback interface crosses the public UniFFI surface. Generated async completion callbacks are binding internals; Core's client remains `Send + Sync` | no public reentry surface |
| Error mapping | Kotlin and Swift smoke checks assert stable numeric error codes for invalid input, unsupported transport, and closed clients | covered |
| Secret diagnostics | Rust `ClientConfig` redaction plus generated Kotlin, Swift, Python, and Go redaction; PTT release logs no longer emit full PTT receive events | covered |
| Key storage | Android Keystore AES-GCM wrapping; distinct endpoint/storage roots; plaintext arrays cleared after open | covered; rooted-device and unlocked-process compromise remain platform risks |
| Backup and restore | `allowBackup=false`, `fullBackupContent=false`, Android 12+ extraction rules, and `noBackupFilesDir`; restore tests cover persisted application state | covered; no identity migration by design |
| Exported Android components | ATAK invitation deep link intentionally public; scanner private; ATAK host component required; PTT overlay/restore private; accessibility service protected by `BIND_ACCESSIBILITY_SERVICE` | covered except IPC blocker below |
| ATAK to PTT IPC sender | ATAK v2 tickets are random, single-use, per workspace and short-lived; API 34 shares sender identity and earlier Android uses PendingIntent creator proof | release blocked until matching PTT trunk implementation lands |
| Release signing/update | ATAK TPP process verifies package, API, ABI, certificate and checksum; PTT release key is external to the repo | documented |

## Residual risks and release conditions

1. Do not release ATAK and PTT together until `ptt-60z.6.1` is integrated and
   tested from both designated trunks. The test must show spoofed, expired,
   replayed, wrong-workspace, and wrong-protocol offers leave an active session
   unchanged.
2. Android Keystore protection does not defend an already unlocked, compromised
   process or rooted device. Hardware-backed enforcement varies by device.
3. Debug builds intentionally expose more diagnostics. Release builds must keep
   payloads, invitations, tickets, endpoint secrets, and storage roots out of
   logs and crash metadata.
4. Core pin `f7d78b0` predates the ready regression fix branch
   `security/core-hardening-regressions`; SDK network smoke remains subject to
   that integration order.
