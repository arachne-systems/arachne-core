# Arachne Core

Portable Rust primitives for workspace-scoped collaboration.

This pre-release repository contains the reusable Arachne core: workspace security,
encrypted local records, payload-neutral delivery, peer connectivity and the
runtime seam that composes them. ATAK, Android/JNI, Kotlin, CoT translation,
release packaging and relay services remain outside this repository.

## Status

**Pre-release alpha extraction — not yet published.**

The project is intended for public release, but this candidate is still under
product validation. The core packages now use the `arachne-*` namespace and
expose a typed `arachne-runtime::Client` for native consumers. The older request
dispatcher is kept internally for the existing adapter boundary. A passing local
test run is not a WAN, relay or operational-readiness claim.

## Packages

| Package | Responsibility |
| --- | --- |
| `arachne-runtime` | Typed lifecycle, workspace, admission, recovery and publication client |
| `arachne-node` | Authenticated peer connections, routes, control and resource transfer |
| `arachne-routing` | Workspace/topic publication scope and delivery policy |
| `arachne-delivery` | Publication indexes, current views and retained delivery state |
| `arachne-security` | Workspace membership, invitations, profiles and protected records |
| `arachne-store` | Atomic encrypted local records and freshness checks |

The core carries opaque application payloads. Chat, PLI, points, packages and
feeds are application or ATAK adapter concerns, not core protocol types.

## Boundary and limits

- Admission and workspace state are authenticated and workspace-scoped.
- Local records use atomic encrypted persistence; callers still own the final
  save/readback/adopt transaction for operations that advance application state.
- The recovery callback queue is live and bounded; it is not a durable
  application outbox or delivery acknowledgement ledger.
- Membership history, profile/name retention and invitation controls are
  bounded by the current implementation and are not a general conflict-
  reconciliation service.
- Direct, local and configured WAN/relay route profiles are testable in Rust;
  production relay availability, NAT traversal and impaired-network behavior
  remain qualification evidence rather than guarantees.

These limits are intentional release boundaries. They are recorded in
[`CORE_STATUS.md`](CORE_STATUS.md) and should not be hidden by calling this
repository a finished SDK.

## Build and test

Run from the repository root with the pinned Rust toolchain:

```sh
cargo +1.98.0 check --locked --offline --workspace
cargo +1.98.0 test --locked --offline --workspace -- --test-threads=1
```

Serial execution matters because some runtime tests exercise a process-wide
session-capacity budget. The workspace has no Android member and these checks
do not require ATAK, an APK or a device.

## Repository layout

```text
crates/    the six portable Arachne packages
docs/      core architecture, domain and security contracts
vendor/    pinned upstream dependencies with narrow Arachne patches
```

## Licensing

Arachne-owned core source is licensed under the [Mozilla Public License 2.0](LICENSE).
The MPL grant is the public open-source license for this core. A separate
commercial agreement may add support, indemnity, OEM terms or proprietary
modification rights where Arachne has the necessary rights; it does not remove
the MPL rights.

This is a pre-release repository and is not yet published. ATAK/Android inputs,
vendored dependencies and third-party notices retain their own terms. See
[`LICENSING.md`](LICENSING.md) for the boundary.
