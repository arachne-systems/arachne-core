//! General file transfer over the node's existing authenticated blob protocol.
use super::*;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct ResourceTicket {
    #[serde(with = "crate::client_wire::id")]
    pub hash: Key32,
    pub size: u64,
    #[serde(with = "crate::client_wire::id")]
    pub grant: Key32,
}

#[non_exhaustive]
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum ResourceRequest {
    Prepare {
        member: MemberId,
        root: String,
        path: String,
    },
    Fetch {
        member: MemberId,
        root: String,
        path: String,
        ticket: ResourceTicket,
    },
    Poll {
        id: u64,
    },
    Cancel {
        id: u64,
    },
    Revoke {
        path: Option<String>,
    },
    Clear {
        root: String,
    },
}

#[non_exhaustive]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ResourceStatus {
    Started { id: u64 },
    Running { bytes: u64 },
    Prepared { ticket: ResourceTicket },
    Complete { bytes: u64 },
    Cancelled,
    Revoked,
    Cleared,
}

impl From<arachne_node::resources::ResourceTicket> for ResourceTicket {
    fn from(value: arachne_node::resources::ResourceTicket) -> Self {
        Self {
            hash: value.hash.into(),
            size: value.size,
            grant: value.grant.into(),
        }
    }
}
impl From<ResourceTicket> for arachne_node::resources::ResourceTicket {
    fn from(value: ResourceTicket) -> Self {
        Self {
            hash: value.hash.to_bytes(),
            size: value.size,
            grant: value.grant.to_bytes(),
        }
    }
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl Client {
    /// Start, poll, cancel or revoke a resource transfer. Member authorization
    /// and path confinement run in the existing native resource service.
    pub fn resource(&self, request: ResourceRequest) -> Result<ResourceStatus> {
        use crate::resources::Request as R;
        let request = match request {
            ResourceRequest::Prepare { member, root, path } => R::Prepare {
                member: member.to_bytes(),
                root: root.into(),
                path: path.into(),
            },
            ResourceRequest::Fetch {
                member,
                root,
                path,
                ticket,
            } => R::Fetch {
                member: member.to_bytes(),
                root: root.into(),
                path: path.into(),
                ticket: ticket.into(),
            },
            ResourceRequest::Poll { id } => R::Poll { id },
            ResourceRequest::Cancel { id } => R::Cancel { id },
            ResourceRequest::Revoke { path } => R::Revoke {
                path: path.map(Into::into),
            },
            ResourceRequest::Clear { root } => R::Clear { root: root.into() },
        };
        self.call(Op::Resource, |session| {
            crate::resources::execute(session, request)
        })
    }
}
