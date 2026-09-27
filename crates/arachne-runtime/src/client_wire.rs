//! The remaining JSON adapter uses byte arrays on the wire. Public ID types
//! use hex in their own serde form. Keep the old wire shape explicit here.
use arachne_api::{ApiError, AttemptId, EndpointId, Key32, MemberId, RecordId, WorkspaceId};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub(crate) trait WireId: Sized {
    fn bytes(&self) -> &[u8];
    fn from_wire(bytes: &[u8]) -> Result<Self, ApiError>;
}
macro_rules! ids { ($($id:ty),+ $(,)?) => { $(
    impl WireId for $id {
        fn bytes(&self) -> &[u8] { self.as_bytes() }
        fn from_wire(bytes: &[u8]) -> Result<Self, ApiError> { Self::from_slice(bytes) }
    }
)+ }; }
ids!(
    AttemptId,
    EndpointId,
    Key32,
    MemberId,
    RecordId,
    WorkspaceId
);

pub(crate) mod id {
    use super::*;
    pub fn serialize<T: WireId, S: Serializer>(id: &T, serializer: S) -> Result<S::Ok, S::Error> {
        id.bytes().serialize(serializer)
    }
    pub fn deserialize<'de, T: WireId, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<T, D::Error> {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        T::from_wire(&bytes).map_err(serde::de::Error::custom)
    }
}
pub(crate) mod many {
    use super::*;
    pub fn serialize<T: WireId, S: Serializer>(
        ids: &[T],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        ids.iter()
            .map(WireId::bytes)
            .collect::<Vec<_>>()
            .serialize(serializer)
    }
}
