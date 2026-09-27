# Security release gates

These gates apply to Core, the generated SDK, the ATAK plugin, and the PTT app.
Record the exact commit of each repository and attach command output to the
release candidate. A checked box without a receipt is not evidence.

## Required for every release

1. **Private reporting works.** Open the link in `SECURITY.md` while signed out
   far enough to confirm that a reporter can submit privately. GitHub private
   vulnerability reporting must be enabled on `arachne-core`.
2. **No unaccepted high severity work.** Query Beads for the `security-program`
   epic and its descendants. No open P0 or P1 finding may affect the candidate.
   An exception must name an owner, scope, compensating control, and expiry no
   later than 30 days; include it in the release notes.
3. **Threat model is current.** Review changes since the last release against
   `docs/threat-model.md` and the protocol integration review. New trust
   boundaries, metadata, keys, persistence, or exported Android components must
   update the model before release.
4. **Dependency and source policy passes.** Run `cargo deny --all-features check`
   from Core. Resolve advisories or record a time-bounded exception. Confirm every
   vendored patch is still listed in the vendor exit review.
5. **Protocol regressions pass.** Run the security, gossip, Tor, node, and runtime
   suites named by the current protocol review. Include pass, fail, and ignored
   counts. Known failures block the release.
6. **Fuzz smoke passes.** Run all four committed targets for 1,000 iterations or
   30 seconds each using the pinned nightly and corpus in `docs/fuzzing.md`.
   Preserve and minimize every crash before proceeding.
7. **Generated SDK is reproducible.** Regenerate all bindings, reject drift, and
   run every language smoke test. The SDK Core pin must be a commit on the Core
   trunk. No secret may appear in generated diagnostic strings.
8. **Android boundaries pass.** Run the ATAK host checks and PTT JVM checks. Review
   the merged manifests for exported components, backup/device transfer, release
   signing, permissions, and debug-only diagnostics. ATAK and PTT must use the
   same version of their IPC protocol.
9. **Artifacts are attributable.** Produce SBOM and provenance attestations for
   Core/SDK packages. Verify the TPP signer certificate and checksum for ATAK and
   the configured release signer for PTT. Never publish a local debug-signed APK.
10. **Release claims match evidence.** Tor or public-relay production claims need
    a current live qualification receipt. Cryptographic production claims need
    the independent protocol review required by the protocol integration review.

## Emergency dependency release

For an exploited dependency, create a private advisory, identify reachable use,
pin the fixed dependency, and run the smallest affected protocol and product
path first. The release owner may defer unrelated gates for at most 7 days, but
must record what was skipped and complete it after the emergency artifact ships.
P0/P1 product-path failures, signing checks, and disclosure-path checks cannot be
deferred.

## Compromise response

- **Endpoint key:** stop the endpoint, remove it from every workspace, rotate the
  endpoint key, and re-invite only after the removal commit is durable. Treat
  address bindings signed by the old key as untrusted.
- **MLS leaf/private state:** remove the member and re-invite it. A normal
  self-update supplies post-compromise key rotation only when the attacker no
  longer controls the member process.
- **Storage root or database:** assume saved history is exposed. Preserve a copy
  for incident analysis, create fresh protected storage, and restore only from a
  trusted state. There is no in-place claim that erases prior disclosure.
- **Release signing key:** stop distribution, revoke or replace the key through
  the relevant store/TPP, publish checksums and affected versions, and ship a
  newly signed replacement. Do not overwrite prior artifacts silently.

See `docs/reviews/2026-09-27-compromise-revocation-exercise.md` for the first
recorded exercises.
