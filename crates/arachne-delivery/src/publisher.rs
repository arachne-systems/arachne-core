//! Per-epoch publisher logs ("what was sent") with one authorization rule
//! ("who may recover"): the requester is a CURRENT member under the CURRENT
//! policy, and was already a member in the requested epoch.
use super::*;

const MAGIC: &[u8] = b"DFPL\x01";
/// Encoded bound of the whole publisher log. Together with `INBOX_BUDGET`
/// it fits one workspace attachment, so saving never evicts either.
pub const PUBLISHER_BUDGET: usize = 192 * 1024;
/// Endpoints admitted after one epoch, per retained epoch. A batch admits at
/// most 128; the window holds at most `RECEIVE_EPOCHS` later epochs.
const MAX_JOINED_AFTER: usize = 128 * arachne_security::RECEIVE_EPOCHS as usize;

#[derive(Clone)]
struct Retained {
    /// Keys the log to one branch of this epoch (ADR A2 step 10).
    fingerprint: [u8; 32],
    /// Endpoints admitted after this epoch. They never get its history.
    joined_after: BTreeSet<[u8; 32]>,
    log: EpochLog,
}

/// The author's retained publications for the current epoch and the
/// `RECEIVE_EPOCHS` epochs before it. Sending appends to the current epoch
/// only. Clone to stage with security; save with the owner.
#[derive(Clone)]
pub struct PublisherLog {
    workspace: [u8; 32],
    author: [u8; 32],
    /// Ascending epochs. The last entry is the current epoch.
    epochs: Vec<Retained>,
}

impl PublisherLog {
    pub fn new(owner: &arachne_security::Workspace) -> Result<Self, &'static str> {
        let author = owner.member().ok_or("publisher requires member identity")?.id();
        Ok(Self {
            workspace: owner.id(),
            author,
            epochs: vec![Retained {
                fingerprint: owner.epoch_fingerprint(),
                joined_after: BTreeSet::new(),
                log: EpochLog::new(owner.id(), author, owner.epoch()),
            }],
        })
    }

    fn current(&self) -> &EpochLog {
        &self.epochs.last().expect("current epoch log").log
    }

    /// Current epoch.
    pub fn epoch(&self) -> u64 {
        self.current().epoch
    }

    /// Head of the current epoch.
    pub fn head(&self) -> u64 {
        self.current().head
    }

    /// Retained epochs, oldest first.
    pub fn epochs(&self) -> Vec<u64> {
        self.epochs.iter().map(|retained| retained.log.epoch).collect()
    }

    /// The retained log of one epoch.
    pub fn epoch_log(&self, epoch: u64) -> Option<&EpochLog> {
        self.epochs
            .iter()
            .find(|retained| retained.log.epoch == epoch)
            .map(|retained| &retained.log)
    }

    pub(crate) fn validate_owner(
        &self,
        owner: &arachne_security::Workspace,
    ) -> Result<(), &'static str> {
        let current = self.epochs.last().ok_or("empty publisher log")?;
        if owner.id() != self.workspace
            || owner.epoch() != current.log.epoch
            || owner.epoch_fingerprint() != current.fingerprint
            || owner.member().map(|m| m.id()) != Some(self.author)
        {
            return Err("publisher index does not match security owner");
        }
        Ok(())
    }

    /// New publications in the current epoch only.
    pub fn append(
        &mut self,
        context: PublicationContext,
        ciphertext: Vec<u8>,
    ) -> Result<u64, &'static str> {
        let sequence = self
            .epochs
            .last_mut()
            .ok_or("empty publisher log")?
            .log
            .append(context, ciphertext)?;
        // One encoded budget for all epochs: older records give way first.
        self.fit_budget();
        Ok(sequence)
    }

    fn fit_budget(&mut self) {
        while self.snapshot().len() > PUBLISHER_BUDGET && self.evict_oldest() {}
        // Only metadata is left over budget: drop whole old epochs.
        while self.snapshot().len() > PUBLISHER_BUDGET && self.epochs.len() > 1 {
            self.epochs.remove(0);
        }
    }

    /// Evict the oldest record of the oldest epoch that has one. Watermarks
    /// stay, so the gap reads as unavailable, never as complete.
    pub(crate) fn evict_oldest(&mut self) -> bool {
        self.epochs
            .iter_mut()
            .any(|retained| retained.log.evict_oldest())
    }

    /// Carry the logs across an accepted membership step. Epochs older than
    /// the receive window are deleted. Members that `next` adds are recorded
    /// so they never get history from before their join.
    pub fn advance(
        &self,
        previous: &arachne_security::Workspace,
        next: &arachne_security::Workspace,
    ) -> Result<Self, &'static str> {
        self.validate_owner(previous)?;
        if next.id() != self.workspace
            || next.member().map(|m| m.id()) != Some(self.author)
            || next.epoch() <= previous.epoch()
        {
            return Err("publisher log cannot advance to this owner");
        }
        let before: BTreeSet<_> = previous.member_endpoints()?.into_iter().collect();
        let added: Vec<_> = next
            .member_endpoints()?
            .into_iter()
            .filter(|endpoint| !before.contains(endpoint))
            .collect();
        let oldest = next.oldest_receive_epoch();
        let mut epochs: Vec<_> = self
            .epochs
            .iter()
            .filter(|retained| retained.log.epoch >= oldest)
            .cloned()
            .collect();
        for retained in &mut epochs {
            retained.joined_after.extend(added.iter().copied());
        }
        // A membership step is never refused for history's sake: an epoch
        // with too many later joins is dropped (its history is unavailable).
        epochs.retain(|retained| retained.joined_after.len() <= MAX_JOINED_AFTER);
        epochs.push(Retained {
            fingerprint: next.epoch_fingerprint(),
            joined_after: BTreeSet::new(),
            log: EpochLog::new(self.workspace, self.author, next.epoch()),
        });
        let mut advanced = Self {
            workspace: self.workspace,
            author: self.author,
            epochs,
        };
        advanced.fit_budget();
        Ok(advanced)
    }

    /// Current-epoch selection. See `EpochLog::select`.
    pub fn select(
        &self,
        after: u64,
        through: u64,
        topics: &BTreeSet<Topic>,
    ) -> Result<RetainedRange<'_>, RangeError> {
        self.current().select(after, through, topics)
    }

    /// Authorize before disclosing retained data OR history availability. The
    /// host supplies current accepted membership/policy and a transport-bound
    /// peer. The returned log is the requested epoch's.
    pub(crate) fn authorize_history(
        &self,
        owner: &arachne_security::Workspace,
        policy: &arachne_routing::RoutingTable,
        requester: [u8; 32],
        scope: ([u8; 32], [u8; 32], u64),
        revision: u64,
        topics: &BTreeSet<Topic>,
    ) -> Result<&EpochLog, RetrievalError> {
        if self.validate_owner(owner).is_err()
            || scope.0 != self.workspace
            || scope.1 != self.author
        {
            return Err(RetrievalError::Denied);
        }
        let retained = self
            .epochs
            .iter()
            .find(|retained| retained.log.epoch == scope.2)
            .ok_or(RetrievalError::Denied)?;
        if retained.joined_after.contains(&requester) {
            return Err(RetrievalError::Denied);
        }
        authorize_history(owner, policy, requester, self.author, revision, topics)?;
        Ok(&retained.log)
    }

    /// No active subscription is required or installed by a historical request.
    pub fn authorized_range(
        &self,
        owner: &arachne_security::Workspace,
        policy: &arachne_routing::RoutingTable,
        requester: [u8; 32],
        query: &RangeQuery,
    ) -> Result<RetainedRange<'_>, RetrievalError> {
        self.authorize_history(
            owner,
            policy,
            requester,
            (query.workspace, query.author, query.epoch),
            query.policy_revision,
            &query.topics,
        )?
        .select(query.after, query.through, &query.topics)
        .map_err(RetrievalError::History)
    }

    /// Contains ciphertext and membership metadata; encrypt at rest with the
    /// paired security snapshot.
    pub fn snapshot(&self) -> Vec<u8> {
        let mut bytes = MAGIC.to_vec();
        bytes.extend(self.workspace);
        bytes.extend(self.author);
        bytes.push(self.epochs.len() as u8);
        for retained in &self.epochs {
            bytes.extend(retained.fingerprint);
            bytes.extend((retained.joined_after.len() as u16).to_be_bytes());
            for endpoint in &retained.joined_after {
                bytes.extend(endpoint);
            }
            let log = retained.log.snapshot();
            bytes.extend((log.len() as u32).to_be_bytes());
            bytes.extend(log);
        }
        bytes
    }

    /// Validates the codec and binds the current epoch to the restored owner's
    /// epoch and branch fingerprint.
    pub fn restore(owner: &arachne_security::Workspace, bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() > PUBLISHER_BUDGET {
            return Err("publisher snapshot exceeds bounds");
        }
        let author = owner.member().ok_or("publisher requires member identity")?.id();
        let mut input = bytes;
        if take(&mut input, 5)? != MAGIC
            || take(&mut input, 32)? != owner.id()
            || take(&mut input, 32)? != author
        {
            return Err("wrong publisher snapshot scope");
        }
        let count = take(&mut input, 1)?[0] as usize;
        if count == 0 || count > arachne_security::RECEIVE_EPOCHS as usize + 1 {
            return Err("invalid publisher epoch count");
        }
        let mut epochs: Vec<Retained> = Vec::with_capacity(count);
        for _ in 0..count {
            let fingerprint: [u8; 32] = take(&mut input, 32)?.try_into().unwrap();
            let joined = number16(&mut input)?;
            if joined > MAX_JOINED_AFTER {
                return Err("invalid publisher join record");
            }
            let mut joined_after = BTreeSet::new();
            for _ in 0..joined {
                let endpoint: [u8; 32] = take(&mut input, 32)?.try_into().unwrap();
                if joined_after.last().is_some_and(|last| last >= &endpoint) {
                    return Err("noncanonical publisher join record");
                }
                joined_after.insert(endpoint);
            }
            let length = u32::from_be_bytes(take(&mut input, 4)?.try_into().unwrap()) as usize;
            let body = take(&mut input, length)?;
            let epoch = body
                .get(5 + 64..5 + 72)
                .map(|value| u64::from_be_bytes(value.try_into().unwrap()))
                .ok_or("truncated publisher epoch")?;
            if epochs.last().is_some_and(|last| last.log.epoch >= epoch)
                || epoch < owner.oldest_receive_epoch()
                || epoch > owner.epoch()
            {
                return Err("invalid publisher epoch order");
            }
            epochs.push(Retained {
                fingerprint,
                joined_after,
                log: EpochLog::restore(owner.id(), author, epoch, body)?,
            });
        }
        if !input.is_empty() {
            return Err("trailing publisher snapshot");
        }
        let log = Self {
            workspace: owner.id(),
            author,
            epochs,
        };
        log.validate_owner(owner)?;
        Ok(log)
    }
}
