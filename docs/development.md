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
registry-compatible versions for normal internal dependencies are configured.
The six first-party packages are configured for crates.io but have not been
published; do not treat a successful local build as a release artifact.

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

`vendor/` contains two Arachne-maintained, publishable forks of Iroh packages:
`arachne-iroh-gossip` and `arachne-iroh-blobs`. Their Rust import names stay
`iroh_gossip` and `iroh_blobs`; each retains upstream provenance, notices, and
MIT/Apache-2.0 terms. They are not official Iroh releases.

The root `[patch.crates-io]` still selects local copies of `bao-tree`,
`netlink-packet-core`, and `hax-lib-macros` for this workspace. Those patches
are not part of the Arachne crate dependencies; the clean-consumer check must
therefore build without them. Keep their upstream copyright, license, and
notice files intact, and do not imply that the Arachne MPL license replaces
their terms.

When updating a patched dependency:

1. Record the exact upstream repository and commit/tag for the imported copy.
2. Review the local diff against that upstream revision and keep only intended
   changes.
3. Re-check the dependency's license and required notices.
4. Update `Cargo.lock`, run the relevant crate tests, and include the patch
   rationale in the change.

The complete inventory of source checked into `vendor/` is in
[`THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md); each entry links to its
upstream license and patch/provenance record. Cargo registry dependencies remain
separate packages with their own declared license terms. The vendor inventory is
not an application-binary notice set: create target- and feature-specific
notices when bundling Core into a binary distribution.

## Crates.io release gate

`arachne-node` depends on the two named Arachne Iroh forks so their required
APIs are ordinary registry dependencies, not workspace-only patches. The
other three vendor patches are deliberately not part of published package
manifests. A clean consumer build outside this workspace is the release gate;
it must resolve registry-compatible package names and dependencies without
inheriting this root manifest's `[patch.crates-io]` entries.

Publish in dependency order: `arachne-routing`, `arachne-security`, and
`arachne-store`; then `arachne-delivery`, `arachne-iroh-gossip`, and
`arachne-iroh-blobs`; then `arachne-node`; finally `arachne-runtime`. Cargo
cannot resolve an unpublished first-party dependency while verifying its
dependent package. The release selectors are:

| Order | Package | Selector from repository root |
| --- | --- | --- |
| 1 | `arachne-routing` | `-p arachne-routing` |
| 2 | `arachne-security` | `-p arachne-security` |
| 3 | `arachne-store` | `-p arachne-store` |
| 4 | `arachne-delivery` | `-p arachne-delivery` |
| 5 | `arachne-iroh-gossip` | `--manifest-path vendor/iroh-gossip/Cargo.toml` |
| 6 | `arachne-iroh-blobs` | `--manifest-path vendor/iroh-blobs/Cargo.toml` |
| 7 | `arachne-node` | `-p arachne-node` |
| 8 | `arachne-runtime` | `-p arachne-runtime` |

For each selector, run `cargo publish --dry-run <selector>`, then
`cargo publish <selector>` only after the exact release commit and version are
approved. Wait for the package to appear in the registry index before moving to
the next dependent package; do not publish the workspace as one batch. Before
the first upload, confirm crate-name availability and ownership and establish a
crates.io publisher account. Store authentication in Cargo's user-level
credentials, never in this repository. The names returned 404 from the sparse
index on 2026-09-22; names are first-come and that observation does not reserve
them. Each uploaded version is effectively permanent: it cannot be overwritten
or deleted, and yanking does not remove its source archive. See the [Cargo
publishing guide](https://doc.rust-lang.org/cargo/reference/publishing.html).

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
