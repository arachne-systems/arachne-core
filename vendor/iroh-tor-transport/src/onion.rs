// Added by Arachne Systems (not in iroh-tor-transport 0.1.0); see ARACHNE-PATCH.md.
//! Tor v3 onion service key and address encoding.
//!
//! Replaces the parts of `torut::onion` that this crate used. The encodings
//! follow Tor's rend-spec-v3 and produce the same bytes as torut 0.2.1.

use std::fmt;

use data_encoding::{BASE32_NOPAD, BASE64};
use sha2::{Digest as _, Sha512};
use sha3::{Digest as _, Sha3_256};

/// Onion address version byte for v3 onion services.
const ONION_V3_VERSION: u8 = 0x03;

/// Expanded Ed25519 secret key in the form that Tor's `ADD_ONION ED25519-V3`
/// command takes: the clamped scalar followed by the hash prefix.
#[derive(Clone)]
pub(crate) struct ExpandedSecretKey([u8; 64]);

impl ExpandedSecretKey {
    /// Expand an Ed25519 seed (an iroh `SecretKey`) as RFC 8032 section 5.1.5
    /// does: `SHA-512(seed)`, then clamp the low 32 bytes into the scalar.
    pub(crate) fn from_seed(seed: &[u8; 32]) -> Self {
        let mut expanded: [u8; 64] = Sha512::digest(seed).into();
        expanded[0] &= 248;
        expanded[31] &= 63;
        expanded[31] |= 64;
        Self(expanded)
    }

    /// Key blob for `ADD_ONION ED25519-V3:<blob>`: the 64 bytes in standard
    /// base64 with padding.
    pub(crate) fn key_blob(&self) -> String {
        BASE64.encode(&self.0)
    }

    #[cfg(test)]
    pub(crate) fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

impl fmt::Debug for ExpandedSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ExpandedSecretKey(****)")
    }
}

/// Tor v3 onion address of an Ed25519 public key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct OnionAddressV3 {
    public_key: [u8; 32],
}

impl OnionAddressV3 {
    pub(crate) fn from_public_key(public_key: &[u8; 32]) -> Self {
        Self {
            public_key: *public_key,
        }
    }

    /// Parse a service id (the 56 characters before `.onion`) and check its
    /// version and checksum.
    pub(crate) fn from_service_id(service_id: &str) -> Option<Self> {
        if service_id.len() != 56 {
            return None;
        }
        let raw = BASE32_NOPAD
            .decode(service_id.to_ascii_uppercase().as_bytes())
            .ok()?;
        let raw: [u8; 35] = raw.try_into().ok()?;
        let public_key: [u8; 32] = raw[..32].try_into().ok()?;
        let address = Self::from_public_key(&public_key);
        (address.raw_bytes() == raw).then_some(address)
    }

    /// `CHECKSUM = SHA3-256(".onion checksum" || PUBKEY || VERSION)[..2]`.
    fn checksum(&self) -> [u8; 2] {
        let mut hasher = Sha3_256::new();
        hasher.update(b".onion checksum");
        hasher.update(self.public_key);
        hasher.update([ONION_V3_VERSION]);
        let digest = hasher.finalize();
        [digest[0], digest[1]]
    }

    /// `PUBKEY || CHECKSUM || VERSION`.
    fn raw_bytes(&self) -> [u8; 35] {
        let mut raw = [0u8; 35];
        raw[..32].copy_from_slice(&self.public_key);
        raw[32..34].copy_from_slice(&self.checksum());
        raw[34] = ONION_V3_VERSION;
        raw
    }

    /// Lowercase base32 of the raw bytes, without `.onion`.
    pub(crate) fn service_id(&self) -> String {
        BASE32_NOPAD.encode(&self.raw_bytes()).to_ascii_lowercase()
    }
}

impl fmt::Display for OnionAddressV3 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.onion", self.service_id())
    }
}

impl fmt::Debug for OnionAddressV3 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OnionAddressV3({})", self.service_id())
    }
}
