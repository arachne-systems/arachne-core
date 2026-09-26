> Written by Claude (AI). Handoff brief H6.

# H6: A9c — crypto dependency bumps

## BLUF

Our crates use sha2 0.10 and hkdf/hmac 0.12. iroh 1.2 and openmls_rust_crypto 0.6 already use
sha2 0.11 and hkdf/hmac 0.13, so the tree has two copies. Move our crates to the newer versions.
Keep aes-gcm at 0.10, because openmls_rust_crypto 0.6 uses 0.10. Start after H1 and H2 merge,
because this touches hashing code in every crate.

## Facts (checked on crates.io, 2026-09-24)

- `openmls_rust_crypto` 0.6.0: sha2 ^0.11, hkdf ^0.13, hmac ^0.13, aes-gcm ^0.10.
- sha2 0.10 stays in the tree anyway through ed25519-dalek 2, p256 and p384.
- Done already (`a227d9a`): rusqlite 0.40.2 (SQLite 3.53.2), getrandom 0.4 in our crates.

## Work

- [x] sha2 → 0.11 in every workspace crate. The `digest` 0.11 API changed (output arrays); fix call sites.
- [x] hkdf and hmac → 0.13.
- [x] Keep aes-gcm 0.10. Write the reason in `Cargo.toml`.
- [x] sframe 2.0: read its changelog, check what crypto versions it needs, bump only if it adds no duplicate crates.
- [x] Update `deny.toml` skips: the skip list must match the real duplicates. `cargo deny --all-features check` must pass.
- [x] MSRV check: `cargo +1.91.0 check --locked --workspace`.

## Done when

- `cargo deny` passes with fewer duplicate crypto crates than before.
- The full workspace suite passes.

## Result (2026-09-26)

The work checklist is complete. The Rust 1.91 check, cargo-deny and corrected full suite
pass. The suite has 681 passed, zero failed and 20 ignored tests across 118 executables,
including example harnesses. The owned target directory was removed (7.2 GiB).
See [the H6 evidence](../../evidence/h6-night-2026-09-26.md) for the original RED results,
fixture corrections, final receipts and test limits.

The duplicate-count condition above remains unmet. Nine owned direct dependency edges
now use the requested crypto generation. The resolved graph adds no package or duplicate
version. Three old versions still serve upstream elliptic-curve and dalek dependencies.
The lead accepted this scope limit. H6 does not force unrelated upstream crypto upgrades.
