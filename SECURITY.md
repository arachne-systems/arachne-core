# Security policy

## Report a vulnerability privately

Use [Arachne Core private vulnerability reporting](https://github.com/arachne-systems/arachne-core/security/advisories/new)
for vulnerabilities in Arachne Core, the generated SDK, the ATAK plugin, or the
PTT app. Include the affected repository and commit, impact, reproduction steps,
and any known workaround. Do not open a public issue for an undisclosed
vulnerability or include live secrets, invitations, keys, or operational data.

The private reporting feature must be enabled on `arachne-core` before a release;
the release gate treats an unavailable form as a blocker.

## What to expect

- acknowledgement within 3 business days;
- initial severity and scope assessment within 7 calendar days;
- a status update at least every 14 calendar days while remediation is active;
- coordinated disclosure after a fix is available, normally within 90 days,
  with a shorter timeline for active exploitation.

We may ask for a proof of concept or environment details. We will credit the
reporter unless they request otherwise. Please allow a reasonable remediation
window before publication.

## Supported versions

Until the first stable release, only the latest published prerelease and the
designated trunk of each repository receive security fixes. Older snapshots and
unmerged feature branches are unsupported. A security release may retire a
vulnerable prerelease immediately.

## Maintainer handling

Keep reports in a private advisory. Assign an owner, severity, affected versions,
and embargo target. Fix each repository on its own security branch, test the
complete affected product path, and publish advisories only after replacement
artifacts and upgrade guidance are ready. Follow the
[security release gates](docs/security-release-gates.md) for every release.
