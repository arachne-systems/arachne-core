# Arachne bounded resource transfers

Upstream: iroh-blobs 0.103.0, crates.io archive SHA-256
`5be50b0e2d0a9ba65cee4e0dfb708b3704e02ad12bd4c14c6307e94245943126`.
MIT/Apache-2.0 licenses and published source are retained. Package-local lockfiles
and Cargo registry bookkeeping are omitted; the root lockfile is authoritative.
Trailing whitespace and extra EOF blank lines in upstream documentation and
workflow/configuration files are normalized.

Small host-integration changes, with no Bao, wire, hashing or crypto changes:

- Disable unused genawaiter proc-macro and postcard heapless defaults. Arachne
  uses the generator API and std/alloc serialization, not those optional helpers.
- Make standalone tickets optional (still on in upstream default features).
  Arachne uses workspace/recipient-bound grants, not public bearer blob tickets.
  This avoids pulling in another unused heapless/atomic-polyfill dependency.
- Export the existing `gc_run_once` function. Arachne serializes calls so changing
  the single resumable partial reclaims obsolete bytes before another download.
- Bound the file-store runtime to two workers per workspace instead of one per CPU.
- Declare the Tokio runtime features the file-store crate uses, rather than
  relying on feature unification from Arachne's host workspace.
- The copied CLI example rejects non-UTF-8 arguments explicitly, rather than
  panicking during argument decoding. It is not included in Arachne binaries.

- Depend on the renamed `arachne-bao-tree` fork (`=0.16.1-arachne.1`, see
  `vendor/bao-tree/ARACHNE-PATCH.md`) with `package =` and a path. The
  dependency key stays `bao-tree`, so `bao-tree/fs` and `use bao_tree` are
  unchanged. This replaces the earlier workspace-only `[patch.crates-io]`, so
  the fix now reaches downstream consumers.

Package identity and other file changes (normalized `Cargo.toml` and docs):
`name = "arachne-iroh-blobs"`, version `0.103.0-arachne.1`, "Arachne Systems"
added to `authors`, new `description`, an `arachne` keyword, and new
`repository`, `homepage`, `documentation`, `publish = ["crates-io"]` and
`exclude = ["Cargo.toml.orig"]` fields. `README.md` has a fork banner.
`Cargo.toml.orig` is the unchanged upstream original. Source changes are in
`src/lib.rs` (`ticket` module behind the `tickets` feature), `src/store/fs.rs`
(`worker_threads(2)`), `src/store/mod.rs` (export `gc_run_once`) and
`examples/transfer.rs`. The other differences are whitespace normalization in
`CHANGELOG.md`, `DESIGN.md`, `.config/nextest.toml` and `.github/workflows/`.

The earlier `arachne-iroh-blobs` 0.103.0 release reused the upstream number.
Under semver it sorts above `0.103.0-arachne.1`, so dependents must pin the fork
with `=`. Fork versions use `<upstream version>-arachne.<N>`.

Remove each change when the corresponding upstream feature/API is available.
`crates/arachne-node/tests/resource_stream.rs` checks >100 MiB streaming, verified
resume, recipient/hash/length authorization, revocation and external-file safety.
These checks qualify our narrow usage, not every upstream feature. Upstream's
0.103 README still cautions that this major API is not production quality;
tablet, release security and pre-TPP gates remain required.
