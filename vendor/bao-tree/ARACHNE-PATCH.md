# Arachne dependency feature selection

Upstream: bao-tree 0.16.1, crates.io archive SHA-256
`149a2a6017771141e2cd5d0c55b3892d8ff1958df5c318b2e496bf3544b426ed`.
MIT/Apache-2.0 licenses and published source are retained. The root lockfile is
authoritative; package-local lockfiles/registry bookkeeping are omitted.

Published as the renamed fork `arachne-bao-tree`, version `0.16.1-arachne.1`.
The Rust library name stays `bao_tree`. `arachne-iroh-blobs` depends on it
directly (`bao-tree = { package = "arachne-bao-tree", version = "=0.16.1-arachne.1" }`).
Thus the change reaches downstream consumers of the Arachne crates. A root
`[patch.crates-io]` entry applies only inside this workspace, so this fork does
not use one.

Complete list of differences from the published upstream archive:

- Normalized `Cargo.toml`: `genawaiter` default features are disabled. Bao's
  generator API does not use the optional procedural macros that would pull in
  the unmaintained `proc-macro-error` package.
- Normalized `Cargo.toml` package identity: `name = "arachne-bao-tree"`,
  version `0.16.1-arachne.1`, "Arachne Systems" added to `authors`, and new
  `description`, `keywords`, `repository`, `homepage`, `documentation`,
  `publish = ["crates-io"]` and `exclude = ["Cargo.toml.orig"]` fields.
  The `[lib] name = "bao_tree"` is unchanged.
- `README.md`: a fork banner at the top. Trailing whitespace in the upstream
  README is normalized.
- `ARACHNE-PATCH.md` (this file) is added.

No decoder, verifier, tree, I/O or cryptographic code changes. `Cargo.toml.orig`
is the unchanged upstream original. Remove this fork when upstream selects this
feature set. The real >100 MiB verified transfer/resume check is in
arachne-node.

## Versioning

Fork versions use `<upstream version>-arachne.<N>`. Increase `N` for each
Arachne change on the same upstream base. Dependents use an exact `=` pin,
because the patched source must match.

The package is outside the workspace `members` list (in `exclude`) so that its
upstream dev-dependencies stay out of the root `Cargo.lock`. Thus release-plz
does not publish it. Publish it by hand before `arachne-iroh-blobs`:
`cargo publish --manifest-path vendor/bao-tree/Cargo.toml`.
