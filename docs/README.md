# Core documentation

These guides describe the current implementation in this repository. They are
engineering documentation, not a stable protocol/API specification, security
certification, or deployment approval. Read the limits sections before using
the pre-release crates in an application.

## Start here

- [Architecture](architecture.md) — terms, crate boundaries, data flow, and
  what belongs outside Core.
- [Integration](integration.md) — client lifecycle, network profiles,
  persistence requirements, and API gaps an adapter must account for.
- [Delivery](delivery.md) — delivery contract per mode (group, direct,
  current): at-least-once, duplicates, ordering, loss, recovery, retention and
  epoch behavior.
- [Security](security.md) — security properties, trust boundaries, host duties,
  and known limitations.
- [Threat model](threat-model.md) — cross-repository assets, adversaries,
  invariants, boundary controls, evidence, owners, and residual risks.
- [Development](development.md) — repository layout, Rust commands, test
  coverage map, and vendored dependency maintenance.
- [Fuzzing](fuzzing.md) — untrusted-input targets, bounded CI smoke campaigns,
  corpus handling, and regression minimization.

The [root README](../README.md) is the short project overview. Each crate also
has a short README beside its source. Tests and source are authoritative when a
detail is not covered here.
