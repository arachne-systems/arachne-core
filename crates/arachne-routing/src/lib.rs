//! Payload-independent, workspace-scoped pub/sub routing.
//!
//! This module does NOT authenticate identities or authorize policy changes.
//! The caller must verify policy snapshots and bind every operation's PeerId
//! to its authenticated origin. A transport session alone is insufficient for
//! forwarded messages. No encryption, persistence or delivery guarantee is implied.
mod publication;
pub use publication::PublicationContext;

use std::collections::{BTreeMap, BTreeSet};

pub type WorkspaceId = [u8; 32];
/// Authenticated endpoint key, not a workspace member or human identity.
pub type PeerId = [u8; 32];

const MAX_WORKSPACES: usize = 32;
const MAX_ENDPOINTS: usize = 4096;
const MAX_TOPICS_PER_PEER: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Topic(String);

impl Topic {
    /// Exact, case-sensitive topics. Wildcards are not supported.
    pub fn new(value: impl Into<String>) -> Result<Self, Error> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 128
            || value.split('/').any(str::is_empty)
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/-_.".contains(&b))
        {
            return Err(Error::InvalidTopic);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Topic authorization is independent from subscription interest.
#[derive(Debug, Clone)]
pub enum Permissions {
    AllTopics,
    Selected {
        publish: BTreeSet<Topic>,
        subscribe: BTreeSet<Topic>,
    },
}
impl Default for Permissions {
    fn default() -> Self {
        Self::Selected {
            publish: BTreeSet::new(),
            subscribe: BTreeSet::new(),
        }
    }
}
impl Permissions {
    fn can_publish(&self, topic: &Topic) -> bool {
        match self {
            Self::AllTopics => true,
            Self::Selected { publish, .. } => publish.contains(topic),
        }
    }
    fn can_subscribe(&self, topic: &Topic) -> bool {
        match self {
            Self::AllTopics => true,
            Self::Selected { subscribe, .. } => subscribe.contains(topic),
        }
    }
    fn within_bounds(&self) -> bool {
        match self {
            Self::AllTopics => true,
            Self::Selected { publish, subscribe } => {
                publish.len() <= MAX_TOPICS_PER_PEER && subscribe.len() <= MAX_TOPICS_PER_PEER
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidTopic,
    LimitExceeded,
    UnknownWorkspace,
    WrongPolicyRevision,
    Denied,
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}
impl std::error::Error for Error {}

struct Workspace {
    revision: u64,
    endpoint_permissions: BTreeMap<PeerId, Permissions>,
    subscriptions: BTreeMap<PeerId, BTreeSet<Topic>>,
}

#[derive(Default)]
pub struct RoutingTable {
    workspaces: BTreeMap<WorkspaceId, Workspace>,
}

impl RoutingTable {
    /// Authorized transport endpoints for an already verified policy revision.
    /// This is bootstrap input, never evidence that an endpoint is online.
    pub fn authorized_endpoints(
        &self,
        workspace: WorkspaceId,
        revision: u64,
    ) -> Result<Vec<PeerId>, Error> {
        let state = self
            .workspaces
            .get(&workspace)
            .ok_or(Error::UnknownWorkspace)?;
        if state.revision != revision {
            return Err(Error::WrongPolicyRevision);
        }
        Ok(state.endpoint_permissions.keys().copied().collect())
    }

    /// Check an authenticated transport endpoint against the current policy.
    pub fn authorizes_endpoint(
        &self,
        workspace: WorkspaceId,
        revision: u64,
        peer: PeerId,
    ) -> Result<(), Error> {
        let state = self
            .workspaces
            .get(&workspace)
            .ok_or(Error::UnknownWorkspace)?;
        if state.revision != revision {
            return Err(Error::WrongPolicyRevision);
        }
        if state.endpoint_permissions.contains_key(&peer) {
            Ok(())
        } else {
            Err(Error::Denied)
        }
    }

    /// Publishers to notify about an authorized subscriber's interest.
    pub fn publishers(
        &self,
        workspace: WorkspaceId,
        revision: u64,
        subscriber: PeerId,
        topic: &Topic,
    ) -> Result<Vec<PeerId>, Error> {
        let state = self
            .workspaces
            .get(&workspace)
            .ok_or(Error::UnknownWorkspace)?;
        if state.revision != revision {
            return Err(Error::WrongPolicyRevision);
        }
        if !state
            .endpoint_permissions
            .get(&subscriber)
            .is_some_and(|access| access.can_subscribe(topic))
        {
            return Err(Error::Denied);
        }
        Ok(state
            .endpoint_permissions
            .iter()
            .filter_map(|(peer, access)| access.can_publish(topic).then_some(*peer))
            .collect())
    }

    /// Atomically install an externally verified policy snapshot. Revisions must
    /// increase strictly. Revocation also removes now-unauthorized interests.
    /// The caller must persist accepted revisions to prevent rollback on restart.
    /// This revision describes authorization, not a cryptographic epoch. The map
    /// is an endpoint permission projection, not the workspace member registry.
    pub fn install_verified_policy(
        &mut self,
        workspace: WorkspaceId,
        revision: u64,
        endpoint_permissions: BTreeMap<PeerId, Permissions>,
    ) -> Result<(), Error> {
        if endpoint_permissions.len() > MAX_ENDPOINTS
            || endpoint_permissions.values().any(|p| !p.within_bounds())
            || (!self.workspaces.contains_key(&workspace)
                && self.workspaces.len() >= MAX_WORKSPACES)
        {
            return Err(Error::LimitExceeded);
        }
        if self
            .workspaces
            .get(&workspace)
            .is_some_and(|old| revision <= old.revision)
        {
            return Err(Error::WrongPolicyRevision);
        }
        let mut subscriptions = self
            .workspaces
            .remove(&workspace)
            .map(|old| old.subscriptions)
            .unwrap_or_default();
        subscriptions.retain(|peer, topics| {
            if let Some(access) = endpoint_permissions.get(peer) {
                topics.retain(|topic| access.can_subscribe(topic));
                !topics.is_empty()
            } else {
                false
            }
        });
        self.workspaces.insert(
            workspace,
            Workspace {
                revision,
                endpoint_permissions,
                subscriptions,
            },
        );
        Ok(())
    }

    pub fn subscribe(
        &mut self,
        workspace: WorkspaceId,
        revision: u64,
        peer: PeerId,
        topic: Topic,
    ) -> Result<(), Error> {
        let state = self
            .workspaces
            .get_mut(&workspace)
            .ok_or(Error::UnknownWorkspace)?;
        if state.revision != revision {
            return Err(Error::WrongPolicyRevision);
        }
        if !state
            .endpoint_permissions
            .get(&peer)
            .is_some_and(|access| access.can_subscribe(&topic))
        {
            return Err(Error::Denied);
        }
        let topics = state.subscriptions.entry(peer).or_default();
        if topics.len() >= MAX_TOPICS_PER_PEER && !topics.contains(&topic) {
            return Err(Error::LimitExceeded);
        }
        topics.insert(topic);
        Ok(())
    }

    pub fn unsubscribe(
        &mut self,
        workspace: WorkspaceId,
        revision: u64,
        peer: PeerId,
        topic: &Topic,
    ) -> Result<(), Error> {
        let state = self
            .workspaces
            .get_mut(&workspace)
            .ok_or(Error::UnknownWorkspace)?;
        if state.revision != revision {
            return Err(Error::WrongPolicyRevision);
        }
        if !state.endpoint_permissions.contains_key(&peer) {
            return Err(Error::Denied);
        }
        if let Some(topics) = state.subscriptions.get_mut(&peer) {
            topics.remove(topic);
            if topics.is_empty() {
                state.subscriptions.remove(&peer);
            }
        }
        Ok(())
    }

    /// Current interest only; authorization remains a separate policy check.
    pub fn subscribed(
        &self,
        workspace: WorkspaceId,
        revision: u64,
        peer: PeerId,
        topic: &Topic,
    ) -> Result<bool, Error> {
        let state = self
            .workspaces
            .get(&workspace)
            .ok_or(Error::UnknownWorkspace)?;
        if state.revision != revision {
            return Err(Error::WrongPolicyRevision);
        }
        if !state
            .endpoint_permissions
            .get(&peer)
            .is_some_and(|access| access.can_subscribe(topic))
        {
            return Err(Error::Denied);
        }
        Ok(state
            .subscriptions
            .get(&peer)
            .is_some_and(|topics| topics.contains(topic)))
    }

    /// Select authorized current subscribers; never fall back to workspace-wide
    /// broadcast. Self is included when subscribed. Routing creates no delivery
    /// receipt, retention, queue or duplicate-suppression promise.
    pub fn recipients(
        &self,
        workspace: WorkspaceId,
        revision: u64,
        sender: PeerId,
        topic: &Topic,
    ) -> Result<Vec<PeerId>, Error> {
        let state = self
            .workspaces
            .get(&workspace)
            .ok_or(Error::UnknownWorkspace)?;
        if state.revision != revision {
            return Err(Error::WrongPolicyRevision);
        }
        if !state
            .endpoint_permissions
            .get(&sender)
            .is_some_and(|access| access.can_publish(topic))
        {
            return Err(Error::Denied);
        }
        // ponytail: scan subscribed peers; add a topic index when measured fanout warrants it.
        Ok(state
            .subscriptions
            .iter()
            .filter_map(|(peer, topics)| topics.contains(topic).then_some(*peer))
            .collect())
    }

    /// Validate an explicit endpoint audience, then intersect it with current
    /// subscriptions. The caller resolves members from a verified roster.
    pub fn direct_recipients(
        &self,
        workspace: WorkspaceId,
        revision: u64,
        sender: PeerId,
        topic: &Topic,
        recipients: &[PeerId],
    ) -> Result<Vec<PeerId>, Error> {
        let state = self
            .workspaces
            .get(&workspace)
            .ok_or(Error::UnknownWorkspace)?;
        if state.revision != revision {
            return Err(Error::WrongPolicyRevision);
        }
        if recipients.is_empty()
            || recipients.len() > MAX_ENDPOINTS
            || recipients.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(Error::Denied);
        }
        if !state
            .endpoint_permissions
            .get(&sender)
            .is_some_and(|access| access.can_publish(topic))
        {
            return Err(Error::Denied);
        }
        if recipients.iter().any(|peer| {
            !state
                .endpoint_permissions
                .get(peer)
                .is_some_and(|access| access.can_subscribe(topic))
        }) {
            return Err(Error::Denied);
        }
        Ok(recipients
            .iter()
            .copied()
            .filter(|peer| {
                state
                    .subscriptions
                    .get(peer)
                    .is_some_and(|topics| topics.contains(topic))
            })
            .collect())
    }
}

#[test]
fn all_member_access_still_requires_bounded_explicit_interests() {
    let mut table = RoutingTable::default();
    let workspace = [1; 32];
    let topic = Topic::new("feeds/new-stream").unwrap();
    table
        .install_verified_policy(
            workspace,
            1,
            BTreeMap::from([
                ([1; 32], Permissions::AllTopics),
                ([2; 32], Permissions::AllTopics),
            ]),
        )
        .unwrap();
    assert!(
        table
            .recipients(workspace, 1, [1; 32], &topic)
            .unwrap()
            .is_empty()
    );
    table
        .subscribe(workspace, 1, [2; 32], topic.clone())
        .unwrap();
    assert_eq!(
        table.recipients(workspace, 1, [1; 32], &topic).unwrap(),
        vec![[2; 32]]
    );
    assert!(
        table
            .subscribe(workspace, 1, [3; 32], topic.clone())
            .is_err()
    );
    assert!(table.recipients([9; 32], 1, [1; 32], &topic).is_err());
    table.unsubscribe(workspace, 1, [2; 32], &topic).unwrap();
    assert!(
        table
            .recipients(workspace, 1, [1; 32], &topic)
            .unwrap()
            .is_empty()
    );
    for n in 0..MAX_TOPICS_PER_PEER {
        table
            .subscribe(
                workspace,
                1,
                [2; 32],
                Topic::new(format!("feeds/{n}")).unwrap(),
            )
            .unwrap();
    }
    assert_eq!(
        table.subscribe(workspace, 1, [2; 32], topic.clone()),
        Err(Error::LimitExceeded)
    );
    let retained_topic = Topic::new("feeds/0").unwrap();
    assert_eq!(
        table
            .recipients(workspace, 1, [1; 32], &retained_topic)
            .unwrap(),
        vec![[2; 32]]
    );
    table
        .install_verified_policy(
            workspace,
            2,
            BTreeMap::from([([1; 32], Permissions::AllTopics)]),
        )
        .unwrap();
    assert!(
        table
            .recipients(workspace, 2, [1; 32], &topic)
            .unwrap()
            .is_empty()
    );
    assert!(
        table
            .recipients(workspace, 2, [1; 32], &retained_topic)
            .unwrap()
            .is_empty()
    );
    assert!(table.subscribe(workspace, 2, [2; 32], topic).is_err());
}
