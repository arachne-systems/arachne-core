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

- [ ] sha2 → 0.11 in every workspace crate. The `digest` 0.11 API changed (output arrays); fix call sites.
- [ ] hkdf and hmac → 0.13.
- [ ] Keep aes-gcm 0.10. Write the reason in `Cargo.toml`.
- [ ] sframe 2.0: read its changelog, check what crypto versions it needs, bump only if it adds no duplicate crates.
- [ ] Update `deny.toml` skips: the skip list must match the real duplicates. `cargo deny --all-features check` must pass.
- [ ] MSRV check: `cargo +1.91.0 check --locked --workspace`.

## Done when

- `cargo deny` passes with fewer duplicate crypto crates than before.
- The full workspace suite passes.
