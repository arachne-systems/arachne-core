# Arachne built-in Tor control client (torut removed)

Upstream: `iroh-tor-transport` 0.1.0 (n0-computer/iroh-tor), crates.io archive
SHA-256 `fbfee97781ea97f4ca13b85547b83001d0b489902430ba3da13f45348d070ecf`
(the same checksum Cargo.lock recorded for the registry package). MIT/Apache-2.0
licenses and published source files are retained.

Published as the renamed fork `arachne-iroh-tor-transport`, version
`0.1.0-arachne.1`. The Rust library name stays `iroh_tor_transport`.
Dependents pin the fork with `=`: it is built on iroh's unstable
custom-transport API, and the patched source must match.

## Complete list of differences from the published upstream archive

Found with `diff -ru` against the crates.io archive
(`~/.cargo/registry/cache/*/iroh-tor-transport-0.1.0.crate`).

### Why

Upstream uses `torut` 0.2.1 (last release 2021, unmaintained) for the Tor
control port and onion keys. `torut` depends on `ed25519-dalek` 1.0.1
(RUSTSEC-2022-0093) and `curve25519-dalek` 3.2.0 (RUSTSEC-2024-0344), plus
`sha2` 0.9, `sha3` 0.9, `hmac` 0.11, `base64` 0.13 and `rand` 0.7. The fork
replaces the few `torut` functions that this crate calls with a small,
tested module. No Ed25519 crate is needed: the public key comes from the
iroh `SecretKey`, and the Tor key blob is only a SHA-512 expansion.

### New files

1. **`src/onion.rs`** (replaces `torut::onion`).
   - `ExpandedSecretKey::from_seed`: `SHA-512(seed)`, then clamp bytes 0 and 31
     (RFC 8032 section 5.1.5). This is the same computation as upstream's
     `iroh_to_tor_secret_key`, which moved here.
   - `ExpandedSecretKey::key_blob`: standard base64 with padding of the
     64 bytes, as `ADD_ONION ED25519-V3:<blob>` takes (torut's
     `as_tor_proto_encoded`).
   - `OnionAddressV3`: `base32(PUBKEY || CHECKSUM || 0x03)` in lowercase, with
     `CHECKSUM = SHA3-256(".onion checksum" || PUBKEY || 0x03)[..2]`
     (rend-spec-v3). `from_service_id` parses and checks length, base32,
     version and checksum. `Debug` of the secret key is redacted.
2. **`src/control.rs`** (replaces `torut::control`). Only the commands that
   upstream sends:
   - `PROTOCOLINFO 1`, parsed for `AUTH METHODS=` and an optional
     `COOKIEFILE=` QuotedString (backslash and C octal escapes). Unknown
     methods are ignored (torut rejected the whole reply).
   - `AUTHENTICATE`: the same choice as torut's `make_auth_data`: `NULL` if
     offered; otherwise, if `SAFECOOKIE` or `COOKIE` is offered with a cookie
     file, the first 32 bytes of the file as plain `COOKIE` auth (upper-case
     hex). If no method works without a password, `build()` still skips
     `AUTHENTICATE`, as upstream did. `SAFECOOKIE` challenge-response and
     `HASHEDPASSWORD` are not implemented (torut did not do them either).
   - `ADD_ONION ED25519-V3:<blob> Flags=DiscardPK Port=<port>,<addr> ` with
     the trailing space, byte-for-byte what torut sent. The `ServiceID=` of
     the reply is returned.
   - Reply reader: `NNN-` mid lines and the `NNN ` end line must carry one
     code; a reply is limited to 1 MiB (torut's bound); EOF in a reply is an
     error; `NNN+` data replies (not used by these commands) are rejected.
   - The connection is kept for the life of `TorCustomTransport`, because
     the ephemeral onion service ends when it closes (as with torut).
     `DEL_ONION` is not implemented; upstream did not call it.
   - Public `ControlError` (`Io`, `Protocol`, `Status { code, message }`).

### `src/lib.rs`

- `mod control; mod onion;`, and `pub use control::ControlError`. The torut,
  `sha2` and `Pin` imports and the `EventHandler` type alias are removed.
- **Public API:** the `source` of `BuildError::ProtocolInfo`, `Auth` and
  `CreateOnion` is now `ControlError` instead of `torut::control::ConnError`.
  Variant names and messages are unchanged.
- `iroh_to_tor_secret_key` returns `ExpandedSecretKey`.
  `onion_address_from_endpoint` builds the address directly (still returns
  `Option`, always `Some`: an `EndpointId` is already a validated Ed25519 key,
  which is the check torut made).
- `build()`: same steps and order through the new client. The "already
  exists" case is `ControlError::Status { code: 552, .. }` (was
  `ConnError::InvalidResponseCode(552)`). **New check:** if Tor reports a
  `ServiceID` that does not equal the address derived from the `EndpointId`,
  `build()` fails with `CreateOnion`, because peers could not reach the
  service. The log line prints the address through `Display`.
- The SOCKS connect path formats the address with `Display` (same string).
- In-file change notice on line 1.

### Tests

- `src/tests/mod.rs`: the helper derives the onion address from the public
  key. `test_key_conversion` compared torut's public key with iroh's; it now
  checks the RFC 8032 TEST 1 key blob and onion address pinned to torut's
  output. In-file change notice on line 1.
- `src/onion.rs` and `src/control.rs` unit tests: RFC 8032 TEST 1/2 vectors
  (public keys from the RFC; key blobs, addresses and wire bytes captured from
  torut 0.2.1), torut's own onion-address test vector, checksum/version
  rejection, reply parser bounds and errors, QuotedString decoding, auth
  selection, and an ignored live-Tor test that requires Tor's `ServiceID` to
  equal the derived address.
- Before torut was removed, a temporary test module ran torut and the new
  code side by side (RFC seeds, edge seeds and 64 random keys) and required
  identical expanded keys, public keys, onion addresses, and `PROTOCOLINFO`,
  `AUTHENTICATE` and `ADD_ONION` wire bytes (see the git history of this
  directory).
- Removed: `tests/echo.rs` and its `[[test]]` target. It had only ignored
  live-Tor tests written against the torut API. Arachne's live check is
  `crates/arachne-node/tests/tor_transport.rs` plus the ignored in-crate test
  above.

### Other files

- `Cargo.toml` (normalized manifest): `name = "arachne-iroh-tor-transport"`,
  version `0.1.0-arachne.1`, "Arachne Systems" added to `authors`, new
  `description`, keyword `arachne` added and `networking` dropped (crates.io
  allows five), new `repository`, `homepage`, `documentation`,
  `publish = ["crates-io"]` and `exclude = ["Cargo.toml.orig"]` fields.
  Dependencies: `torut` removed, `sha3 = "0.11.0"` added. The `echo` test
  target is removed. `Cargo.toml.orig` is the unchanged upstream original.
- `README.md`: a fork banner at the top.
- `ARACHNE-PATCH.md` (this file) is added.
- Removed (repository administration, not needed by this workspace build):
  `.cargo_vcs_info.json`, `.github/`, `.gitignore` and the package-local
  `Cargo.lock`.

Remove this fork when upstream `iroh-tor-transport` no longer depends on
`torut` (or on any `ed25519-dalek` 1.x / `curve25519-dalek` 3.x).
