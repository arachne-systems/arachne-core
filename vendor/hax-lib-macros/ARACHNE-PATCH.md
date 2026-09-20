# Arachne dependency remediation

Base: published `hax-lib-macros` 0.3.7, unmodified package name/version.
Source: https://static.crates.io/crates/hax-lib-macros/hax-lib-macros-0.3.7.crate
Archive SHA-256: `28da835a5f153e9f3d0cc1f42ee605a1cfa9093c93348193793d60a1b0908b51`.
Published VCS revision: `d8b5b3d3b666fee8943a351445d2b680105e8ea3`, path
`hax-lib/macros`. Original `Cargo.toml.orig` and all unchanged source are retained.
Package-local lockfile/registry bookkeeping are omitted; consuming workspace
lockfiles are authoritative, as for the other Arachne vendor packages.

The published archive omits its Apache-2.0 license text. `LICENSE` is copied
verbatim from the published VCS revision:
https://raw.githubusercontent.com/cryspen/hax/d8b5b3d3b666fee8943a351445d2b680105e8ea3/LICENSE
SHA-256: `9a50bad5a51e0ad726ea3a7f4b7b758e1b4d1784e6abefe1367f5bf01e972725`.

Backport the macro-package portion of genuine upstream removal commit
https://github.com/cryspen/hax/commit/8f9cb576e58f6cc7e9ed249a7d4439b0f7ed0da7 :

- Remove `proc-macro-error2` from the normalized manifest's `cfg(hax)` dependencies.
- `src/implementation.rs` exactly matches that commit: ordinary `syn::Error`
  compile errors replace abort wrappers, using the already-present `syn`.
  The non-hax implementation and all crypto/proof algorithms are unchanged.
- Add `tests/check-diagnostics.py` to exercise actual rustc diagnostics and
  successful expansion from the built `cfg(hax)` macro library.

Upstream's whole-commit patch SHA-256:
`a97032bd66982081389e98082bfeff7c6b9e8c6a91e7a5aa287ce27659c4b44e`.
No cfg branch is removed or disabled. Upgrading this package alone to 0.4 would
not satisfy the parent's exact 0.3.7 dependency; retire this backport with a
compatible upstream parent upgrade.

Build the macro with its existing nightly requirement and `RUSTFLAGS='--cfg hax'`,
then run `python3 tests/check-diagnostics.py PATH_TO_LIBHAX_LIB_MACROS.so RUSTC`.
The check covers all explicit abort sites, syn parsing, and valid expression
expansion. It does not perform hax proof extraction or cryptographic verification.
