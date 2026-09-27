// Added by Arachne Systems (not in iroh-tor-transport 0.1.0); see ARACHNE-PATCH.md.
//! Tor v3 onion service key and address encoding.
//!
//! Replaces the parts of `torut::onion` that this crate used. The encodings
//! follow Tor's rend-spec-v3 and produce the same bytes as torut 0.2.1.

use std::fmt;

use data_encoding::{BASE32_NOPAD, BASE64};
use sha2::{Digest as _, Sha512};
use sha3::Sha3_256;

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

#[cfg(test)]
mod tests {
    use data_encoding::HEXLOWER;

    use super::*;

    fn hex32(hex: &str) -> [u8; 32] {
        HEXLOWER.decode(hex.as_bytes()).unwrap().try_into().unwrap()
    }

    /// RFC 8032 section 7.1 TEST 1 and TEST 2. The public keys are the RFC's;
    /// torut 0.2.1 derived the same public keys from the expanded keys
    /// (ed25519-dalek 1). Key blobs and onion addresses are torut's output,
    /// captured before torut was removed.
    const VECTORS: [(&str, &str, &str, &str); 2] = [
        (
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "MHyDhk8oM8tCei7xwAoBPP3/J2jZgMCjpSDwBpBN6U+bTwr+KAt0aneGhOdUQlAgV7dHOgPwj5b1o46Sh+Afjw==",
            "25njqamcweflpvkl73j4szahhihoc4xt3ktcgjnpaingr5yhkenl5sid",
        ),
        (
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "aL2e11iC1SgVqXWFyvR5Cn9sazt/ghxeJZoksC5QLlFFZoSCkdrK8iXMY96zSNoxjiwuF7ALgWD5zmv6BHKRHQ==",
            "hvabpq7iioevvevxbktu2g36xsojqlgpf3cjndgazvk7ckxumygcmyyd",
        ),
    ];

    #[test]
    fn key_blob_and_address_match_torut_vectors() {
        for (seed, public, blob, service_id) in VECTORS {
            let seed = hex32(seed);
            assert_eq!(
                iroh::SecretKey::from_bytes(&seed).public().as_bytes(),
                &hex32(public)
            );
            let key = ExpandedSecretKey::from_seed(&seed);
            assert_eq!(key.key_blob(), blob);
            let address = OnionAddressV3::from_public_key(&hex32(public));
            assert_eq!(address.service_id(), service_id);
            assert_eq!(address.to_string(), format!("{service_id}.onion"));
            assert_eq!(OnionAddressV3::from_service_id(service_id), Some(address));
        }
    }

    #[test]
    fn expanded_key_is_clamped_sha512_of_seed() {
        let key = ExpandedSecretKey::from_seed(&[7u8; 32]);
        let hash: [u8; 64] = Sha512::digest([7u8; 32]).into();
        let bytes = key.as_bytes();
        assert_eq!(bytes[0] & 7, 0);
        assert_eq!(bytes[31] & 0xc0, 0x40);
        assert_eq!(bytes[1..31], hash[1..31]);
        assert_eq!(bytes[32..], hash[32..]);
        assert_eq!(BASE64.decode(key.key_blob().as_bytes()).unwrap(), bytes);
        assert_eq!(format!("{key:?}"), "ExpandedSecretKey(****)");
    }

    /// Address from torut's own tests.
    #[test]
    fn parses_and_round_trips_torut_test_address() {
        let id = "p53lf57qovyuvwsc6xnrppyply3vtqm7l6pcobkmyqsiofyeznfu5uqd";
        let address = OnionAddressV3::from_service_id(id).unwrap();
        assert_eq!(address.to_string(), format!("{id}.onion"));
        assert_eq!(
            OnionAddressV3::from_service_id(&id.to_ascii_uppercase()),
            Some(address)
        );
    }

    #[test]
    fn rejects_bad_service_ids() {
        let id = "p53lf57qovyuvwsc6xnrppyply3vtqm7l6pcobkmyqsiofyeznfu5uqd";
        // Wrong length, not base32, bad checksum, bad version.
        assert_eq!(OnionAddressV3::from_service_id(&id[1..]), None);
        assert_eq!(OnionAddressV3::from_service_id(&id.replace('p', "1")), None);
        let mut raw = BASE32_NOPAD
            .decode(id.to_ascii_uppercase().as_bytes())
            .unwrap();
        raw[32] ^= 1;
        let bad_checksum = BASE32_NOPAD.encode(&raw).to_ascii_lowercase();
        assert_eq!(OnionAddressV3::from_service_id(&bad_checksum), None);
        raw[32] ^= 1;
        raw[34] = 2;
        let bad_version = BASE32_NOPAD.encode(&raw).to_ascii_lowercase();
        assert_eq!(OnionAddressV3::from_service_id(&bad_version), None);
    }
}
