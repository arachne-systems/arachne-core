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
   - `AUTHENTICATE`: `NULL` if offered. Otherwise, if Tor gives a cookie
     file, `SAFECOOKIE` if offered, else plain `COOKIE` (the cookie as
     upper-case hex). The cookie file must be exactly 32 bytes, or
     `build()` fails with `AuthMethod`. If no method works without a
     password, `build()` still skips `AUTHENTICATE`, as upstream did.
     `HASHEDPASSWORD` is not implemented.
   - **`SAFECOOKIE` (not in torut, which sent plain `COOKIE` also when only
     `SAFECOOKIE` was offered):** control-spec 3.24. A 32-byte client nonce
     from `getrandom`, `AUTHCHALLENGE SAFECOOKIE <hex nonce>`, then the
     one-line reply `AUTHCHALLENGE SERVERHASH=<64 hex> SERVERNONCE=<64 hex>`
     is parsed (both fields once, no other fields, hex in either case).
     `SERVERHASH` must equal HMAC-SHA256 with key
     `"Tor safe cookie authentication server-to-controller hash"` over
     `cookie || client nonce || server nonce`; the compare is constant time
     (`hmac` `verify_slice`). On a mismatch the client fails closed with
     `ControlError::Protocol` and sends no `AUTHENTICATE`. Otherwise it sends
     `AUTHENTICATE <hex HMAC-SHA256>` with key
     `"Tor safe cookie authentication controller-to-server hash"` over the
     same message. This proves that the control port is the Tor that wrote
     the cookie before the cookie-derived secret is sent.
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
- The outbound stream cache is capped at 64 peers. A new peer evicts an idle
  stream; if all cached streams are active, the send fails with backpressure.
- The raw inbound Tor accept loop reserves one of 64 permits before accepting
  a stream. Each packet read has a 30-second deadline, and a full endpoint
  packet queue drops the datagram instead of retaining the stream task.
- In-file change notice on line 1.

### Tests

- `src/tests/mod.rs`: the helper derives the onion address from the public
  key. `test_key_conversion` compared torut's public key with iroh's; it now
  checks the RFC 8032 TEST 1 key blob and onion address pinned to torut's
  output. In-file change notice on line 1.
- `idle_inbound_streams_are_bounded_and_release_capacity` proves that the
  accept loop stops at its permit count and that an idle framing deadline
  releases capacity for the next stream.
- `src/onion.rs` and `src/control.rs` unit tests: RFC 8032 TEST 1/2 vectors
  (public keys from the RFC; key blobs, addresses and wire bytes captured from
  torut 0.2.1), torut's own onion-address test vector, checksum/version
  rejection, reply parser bounds and errors, QuotedString decoding, auth
  selection, and an ignored live-Tor test that requires Tor's `ServiceID` to
  equal the derived address.
- `SAFECOOKIE` tests against a scripted fake control stream: the expected
  HMACs come from an HMAC-SHA256 written out with plain SHA-256 in the test
  (checked against RFC 4231 case 2) and a vector pinned from Python's `hmac`
  module; the happy path; `SERVERHASH` mismatches (flipped bit, reflected
  client hash, wrong cookie, swapped nonces) fail with no `AUTHENTICATE`
  sent; malformed `AUTHCHALLENGE` replies fail with no `AUTHENTICATE` sent;
  `SAFECOOKIE` is preferred over `COOKIE` end to end with a random nonce;
  cookie files of 0, 31, 33 and 4096 bytes are rejected. The live test was
  run against Tor 0.4.9.11 with `CookieAuthentication 1`
  (`AUTH METHODS=COOKIE,SAFECOOKIE`) and passed through `SAFECOOKIE`.
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
  Dependencies: `torut` removed, `sha3 = "0.11.0"` added, and for
  `SAFECOOKIE` `hmac = "0.13.0"` and `getrandom = "0.4"` added. `sha2` now
  uses 0.11.0. These versions are already in the workspace lock. The HMAC
  constructor imports `KeyInit`, and SHA-2 and SHA-3 share the same `Digest`
  trait. Existing RFC and independent SAFECOOKIE vectors check the wire bytes. The `echo` test
  target is removed. `Cargo.toml.orig` is the unchanged upstream original.
- `README.md`: a fork banner at the top.
- `ARACHNE-PATCH.md` (this file) is added.
- Removed (repository administration, not needed by this workspace build):
  `.cargo_vcs_info.json`, `.github/`, `.gitignore` and the package-local
  `Cargo.lock`.

Remove this fork when upstream `iroh-tor-transport` no longer depends on
`torut` (or on any `ed25519-dalek` 1.x / `curve25519-dalek` 3.x).
