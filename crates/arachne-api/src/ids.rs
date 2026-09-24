//! ID newtypes. Each kind is its own type, so the compiler rejects a
//! `MemberId` where a `WorkspaceId` is expected.
//!
//! These IDs are public identifiers (public keys and digests), not secrets.
//! `Display` and serde use lowercase hex; `Debug` is `Kind(hex)`. Never put key
//! material or tokens in one of these types.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::ApiError;

fn invalid_id(kind: &str, reason: impl Into<String>) -> ApiError {
    ApiError::InvalidId {
        kind: kind.into(),
        reason: reason.into(),
    }
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn decode_hex<const N: usize>(kind: &str, text: &str) -> Result<[u8; N], ApiError> {
    let raw = text.as_bytes();
    if raw.len() != N * 2 {
        return Err(invalid_id(
            kind,
            format!("expected {} hex characters, got {}", N * 2, raw.len()),
        ));
    }
    let mut out = [0u8; N];
    for (slot, [high, low]) in out.iter_mut().zip(raw.as_chunks::<2>().0) {
        match (hex_digit(*high), hex_digit(*low)) {
            (Some(high), Some(low)) => *slot = (high << 4) | low,
            _ => return Err(invalid_id(kind, "not hex")),
        }
    }
    Ok(out)
}

fn write_hex(f: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    bytes.iter().try_for_each(|byte| write!(f, "{byte:02x}"))
}

macro_rules! byte_id {
    ($(#[$doc:meta])* $name:ident, $kind:literal, $len:literal) => {
        $(#[$doc])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; $len]);

        impl $name {
            /// Length in bytes.
            pub const LEN: usize = $len;

            pub const fn from_bytes(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }

            /// Gives `ApiError::InvalidId` when the length is wrong.
            pub fn from_slice(bytes: &[u8]) -> Result<Self, ApiError> {
                <[u8; $len]>::try_from(bytes).map(Self).map_err(|_| {
                    invalid_id(
                        $kind,
                        format!("expected {} bytes, got {}", $len, bytes.len()),
                    )
                })
            }

            /// Parses exactly `2 * LEN` hex characters (either case).
            pub fn from_hex(text: &str) -> Result<Self, ApiError> {
                decode_hex::<$len>($kind, text).map(Self)
            }

            pub const fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }

            pub const fn to_bytes(self) -> [u8; $len] {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write_hex(f, &self.0)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "("))?;
                write_hex(f, &self.0)?;
                f.write_str(")")
            }
        }

        impl FromStr for $name {
            type Err = ApiError;

            fn from_str(text: &str) -> Result<Self, ApiError> {
                Self::from_hex(text)
            }
        }

        impl From<[u8; $len]> for $name {
            fn from(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.collect_str(self)
            }
        }

        // Foreign code sees each ID as a lowercase hex string. Lifting a
        // foreign string validates it with `from_hex`.
        #[cfg(feature = "uniffi")]
        uniffi::custom_type!($name, String, {
            lower: |id| id.to_string(),
            try_lift: |text| Ok($name::from_hex(&text)?),
        });

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let text = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
                Self::from_hex(&text).map_err(serde::de::Error::custom)
            }
        }
    };
}

byte_id!(
    /// A node endpoint public key (32 bytes).
    EndpointId, "endpoint", 32
);
byte_id!(
    /// A workspace member ID (32 bytes).
    MemberId, "member", 32
);
byte_id!(
    /// A workspace ID (32 bytes).
    WorkspaceId, "workspace", 32
);
byte_id!(
    /// An admission attempt ID (32 bytes).
    AttemptId, "attempt", 32
);
byte_id!(
    /// A delivery record ID (16 bytes). Unique per author.
    RecordId, "record", 16
);
byte_id!(
    /// A publication ID (16 bytes).
    PublicationId, "publication", 16
);

/// Maximum topic length in bytes.
pub const MAX_TOPIC_LEN: usize = 128;

/// An exact, case-sensitive topic name.
///
/// Rules (same as `arachne_routing::Topic`): 1 to 128 bytes, only ASCII
/// letters, digits and `/ - _ .`, and no empty `/` segment.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct TopicName(String);

impl TopicName {
    /// Gives `ApiError::InvalidInput { field: "topic", .. }` for a bad name.
    pub fn new(value: impl Into<String>) -> Result<Self, ApiError> {
        let value = value.into();
        let reason = if value.is_empty() || value.len() > MAX_TOPIC_LEN {
            Some("length must be 1 to 128 bytes")
        } else if !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/-_.".contains(&b))
        {
            Some("only ASCII letters, digits and / - _ . are allowed")
        } else if value.split('/').any(str::is_empty) {
            Some("empty path segment")
        } else {
            None
        };
        match reason {
            Some(reason) => Err(ApiError::InvalidInput {
                field: "topic".into(),
                reason: reason.into(),
            }),
            None => Ok(Self(value)),
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TopicName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for TopicName {
    type Error = ApiError;

    fn try_from(value: String) -> Result<Self, ApiError> {
        Self::new(value)
    }
}

impl From<TopicName> for String {
    fn from(value: TopicName) -> Self {
        value.0
    }
}
