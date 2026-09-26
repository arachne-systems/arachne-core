# Licensing

The Mozilla Public License 2.0 in [`LICENSE`](LICENSE) applies to Arachne-authored
source in this repository. Each Arachne package declares the SPDX expression
`license = "MPL-2.0"` via `license.workspace`. Each crate directory has a
`LICENSE` symlink to the root text, so Cargo puts the full license text in each
package archive. This license does not relicense third-party code.

The vendored Iroh forks (`arachne-iroh-blobs`, `arachne-iroh-gossip`,
`arachne-iroh-tor-transport`) and the
other vendored packages keep their upstream SPDX expressions (`MIT OR
Apache-2.0`, `Apache-2.0` or `MIT`). They are not under MPL-2.0.

[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) inventories source checked in
under `vendor/`, whose original license texts and Arachne patch notes remain in
each vendor directory. Other Cargo dependencies are resolved according to
[`Cargo.lock`](Cargo.lock) and retain their own licenses; this vendored-source
inventory is not a complete dependency SBOM. Prepare distribution-specific
notices from the exact target dependency graph before shipping binaries.

## Binary distributions

A binary that contains Arachne code (for example the SDK `cdylib`, an Android
AAR, or an application) is an "Executable Form" under MPL-2.0 section 3.2. Each
such distribution must:

- Tell recipients that the Arachne source code is available under MPL-2.0 and
  how to get it, for example a link to the exact tagged source of
  `https://github.com/arachne-systems/arachne-core` or the published crates.
- Include the MPL-2.0 text, or a link to it, in the notices that ship with the
  binary.
- Include the license and notice texts for every third-party crate compiled
  into that binary. This includes the Apache-2.0 `NOTICE` requirements and the
  modification notices of the vendored forks. Generate this set from the exact
  target and feature graph, for example with `cargo about` or
  `cargo deny list`.

For an AAR, put these notices in the package (for example under
`assets/licenses/` or `META-INF/`) and show them in the application's
open-source notices screen.

The standard MPL-2.0 form applies; the optional Exhibit B notice excluding
secondary-license compatibility is not selected.

This license does not grant rights to ATAK, the TAK SDK, or Arachne trademarks.
Before accepting outside contributions, complete ownership and provenance review
and publish an approved contribution process.
