# Licensing

The Mozilla Public License 2.0 in [`LICENSE`](LICENSE) applies to Arachne-authored
source in this repository; workspace package manifests identify Arachne crates
as `MPL-2.0`. It does not relicense third-party code.

[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) inventories source checked in
under `vendor/`, whose original license texts and Arachne patch notes remain in
each vendor directory. Other Cargo dependencies are resolved according to
[`Cargo.lock`](Cargo.lock) and retain their own licenses; this vendored-source
inventory is not a complete dependency SBOM. Prepare distribution-specific
notices from the exact target dependency graph before shipping binaries.

The standard MPL-2.0 form applies; the optional Exhibit B notice excluding
secondary-license compatibility is not selected.

This license does not grant rights to ATAK, the TAK SDK, or Arachne trademarks.
Before accepting outside contributions, complete ownership and provenance review
and publish an approved contribution process.
