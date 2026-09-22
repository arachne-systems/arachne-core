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
The six first-party packages and two Arachne-maintained Iroh forks are
publishable workspace members. Check crates.io for current publication status;
new crate names require a one-time manual first publish before Trusted
Publishing can be enabled.

## Toolchain and commands

Use the Rust 1.98.0 toolchain recorded in the root README:

```sh
cargo +1.98.0 check --locked --workspace
cargo +1.98.0 test --locked --workspace -- --test-threads=1
```

Published manifests declare Rust 1.91 as the MSRV. Verify that claim with
`cargo +1.91.0 check --locked --workspace` before changing the dependency lock.

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

## Crates.io releases

`arachne-node` depends on the two named Arachne Iroh forks so their required
APIs are ordinary registry dependencies, not workspace-only patches. The
other three vendor patches are deliberately excluded from publishing. A clean
consumer build outside this workspace must resolve registry-compatible
package names and dependencies without inheriting this root manifest's
`[patch.crates-io]` entries.

The `.github/workflows/release-plz.yml` workflow prepares version and changelog
updates through a release PR. Use Conventional Commit types `fix`, `feat`,
`perf`, `refactor`, `security`, `deps`, or `docs`, optionally with a scope;
append `!` for a breaking change (for example, `feat(api)!:`). Other commit
types do not trigger a crate release. Review and merge the generated release PR
to publish in dependency order and create per-crate GitHub tags/releases. Do
not manually bump crate versions for normal releases.

Publishing uses crates.io Trusted Publishing through GitHub Actions OIDC; no
crates.io API token is stored in GitHub. Configure each already-published
crate's trusted publisher, including `arachne-runtime`, with owner
`arachne-systems`, repository `arachne-core`, and workflow filename
`release-plz.yml` (the workflow itself is located at
`.github/workflows/release-plz.yml`). A new crate
must first be uploaded manually with Cargo; configure its trusted publisher
after that initial upload. `arachne-runtime` is temporarily excluded from
release-plz until its Trusted Publisher is configured.

The organization currently blocks `GITHUB_TOKEN` from creating pull requests.
The workflow therefore uses a repository-scoped GitHub App token. Create an
organization-owned app named `Arachne Systems Release Bot`, disable its webhook,
grant only `Contents: read/write` and `Pull requests: read/write`, and install
it only on `arachne-core`. Save its Client ID as the repository Actions
variable `RELEASE_APP_CLIENT_ID` and its private key as the repository Actions
secret `RELEASE_APP_PRIVATE_KEY`.

For a local package-content check, run `cargo package --list -p <crate>` and
`cargo publish --dry-run -p <crate>`. The initial upload is permanent: a
published version cannot be overwritten or deleted, and yanking does not remove
its source archive. See the [Cargo publishing
guide](https://doc.rust-lang.org/cargo/reference/publishing.html) and
[release-plz Trusted Publishing setup](https://release-plz.dev/docs/github/quickstart).

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
