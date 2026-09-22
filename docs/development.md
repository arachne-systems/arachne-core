# Core development guide

## Repository layout

```text
crates/
  arachne-runtime/    typed client, session composition, lower-level operations
  arachne-security/   MLS workspace, invitations, membership, protected messages
  arachne-node/       Iroh connectivity, control traffic, resources
  arachne-routing/    topic permissions, interest, routing decisions
  arachne-delivery/   publication state and recovery
  arachne-store/      encrypted local record store
vendor/               local patch overrides; retain upstream notices
docs/                 integration, architecture, and security guides
```

Each crate has a short README. The root workspace pins direct dependency
versions where interoperability or protocol behavior requires it and uses
`Cargo.lock` to capture the resolved graph. Shared package metadata and
registry-compatible versions for normal internal dependencies are configured,
but all six Arachne crates remain `publish = false`; do not treat a successful
local build as a release artifact.

## Toolchain and commands

Use the Rust 1.98.0 toolchain recorded in the root README:

```sh
cargo +1.98.0 check --locked --workspace
cargo +1.98.0 test --locked --workspace -- --test-threads=1
```

Run from the repository root. Tests are serialized within each test binary
because runtime tests share process-wide session state and capacity. The
workspace build and tests are Rust checks; they do not build the Android plugin,
load the library through JNI, or validate an ATAK host/device deployment.

Useful focused checks while iterating:

```sh
cargo +1.98.0 test --locked -p arachne-security
cargo +1.98.0 test --locked -p arachne-routing
cargo +1.98.0 test --locked -p arachne-delivery
cargo +1.98.0 test --locked -p arachne-store
cargo +1.98.0 test --locked -p arachne-node -- --test-threads=1
cargo +1.98.0 test --locked -p arachne-runtime -- --test-threads=1
```

For the simple transport example:

```sh
cargo +1.98.0 run --locked -p arachne-runtime --example typed_pubsub
```

That example exercises basic routing and transport only; it is not a secure MLS
workspace demonstration. See [Integration](integration.md#publication-paths).

## Test map

| Area | Representative tests | Questions answered |
| --- | --- | --- |
| Membership and security | `arachne-security/tests/` | Invitation, admission, removal/leave, protocol upgrade and protected state behavior. |
| Routing and delivery | `arachne-routing/tests/pubsub.rs`; delivery unit tests | Topic permissions, interest, publication handling, and recovery invariants. |
| Node transport | `arachne-node/tests/` | Local connections, gossip/control traffic, reconnect, resource streams, and selected WAN/relay profiles. |
| Runtime lifecycle | `arachne-runtime/tests/` | Staging/adoption, persistence, join/leave, recovery, state summaries, and typed facade behavior. |
| Encrypted store | `arachne-store/src/tests.rs`; runtime record-storage tests | Record authentication, atomic writes, key/scope checks, and freshness anchors. |

Test names and exact coverage can change. A passing unit/integration suite is
evidence for the exercised code paths only; it does not establish unrestricted
network reachability, production capacity, Android compatibility, or security
certification.

## Vendored dependency patches

The workspace overrides crates.io sources for `iroh-gossip`, `iroh-blobs`,
`bao-tree`, `netlink-packet-core`, and `hax-lib-macros` under `vendor/`. Cargo's
`[patch.crates-io]` entries in the root manifest select those local copies.
They remain third-party code: keep their upstream copyright, license, and
notice files intact, and do not imply that the Arachne MPL license replaces
their terms.

When updating a patched dependency:

1. Record the exact upstream repository and commit/tag for the imported copy.
2. Review the local diff against that upstream revision and keep only intended
   changes.
3. Re-check the dependency's license and required notices.
4. Update `Cargo.lock`, run the relevant crate tests, and include the patch
   rationale in the change.

The per-directory upstream README/license files are retained as provenance
material. A source-provenance and dependency-notice inventory is still a
separate release requirement; this guide is not that inventory.

## Crates.io release gate

Do not enable publishing until a packaged consumer build works without this
workspace's local patches. `arachne-node` uses `iroh-gossip`'s
`Builder::dial_capacity` and `iroh-blobs`' `store::gc_run_once`, which are
provided by our vendored patches. Cargo omits the root `[patch.crates-io]`
overrides from published package manifests, so crates.io consumers would
resolve upstream packages without those Arachne changes. The other vendor
patches also do not transfer to downstream workspaces. Resolve this through
compatible upstream releases or another registry-compatible dependency plan
before removing `publish = false`.

The first-party dependency order is `arachne-routing`, `arachne-security`, and
`arachne-store`, followed by `arachne-delivery` and `arachne-node`, then
`arachne-runtime`. Publish and verify each package in that order; Cargo cannot
resolve a dependent package's registry version before the dependency has been
published. Crates.io releases are effectively permanent, so run the full
package checks and confirm names and ownership immediately before the first
upload.

## Change discipline

- Keep protocol/state transitions in their owning crate; keep platform glue in
  the host application.
- Preserve stage/commit/adopt ordering and add regression coverage when a
  transition changes.
- Do not treat a test fixture or benchmark/evidence artifact as production
  guidance; name evidence by the exact scenario it covers.
- Run `git diff --check` before sharing documentation or code changes.
- Update these docs when observable API behavior, security boundaries, or
  supported integration steps change.

For licensing scope and release gates, see the root
[`LICENSING.md`](../LICENSING.md). For the user-facing project summary, see the
[root README](../README.md).
