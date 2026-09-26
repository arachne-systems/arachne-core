//! Typed retained-content recovery. Every accepted result uses native save/adopt.
use super::*;
use crate::ops::recovery as ops_recovery;

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct DirectRecoveryRequest {
    pub author: MemberId,
    pub revision: u64,
    pub topic: String,
    pub recipients: Vec<MemberId>,
    pub after: u64,
    pub through: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct DirectRecoveryReady {
    pub workspace: WorkspaceId,
    pub author: MemberId,
    pub peer: EndpointId,
    pub epoch: u64,
    pub revision: u64,
    pub topic: String,
    pub after: u64,
    pub through: u64,
    pub packet_count: u64,
    pub retained_bytes: u64,
    pub attempted: u64,
}

#[non_exhaustive]
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum DirectRecoveryStatus {
    SourceWaiting,
    Pending { candidate_count: u64 },
    Ready { range: DirectRecoveryReady },
    SourceUnavailable { attempted: u64, reason: String },
    Cancelled,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CurrentViewRequest {
    /// None discovers authorized holders through the existing fabric paths.
    pub peer: Option<EndpointId>,
    pub authority: MemberId,
    pub revision: u64,
    pub topic: String,
    pub selector: Key32,
}

#[non_exhaustive]
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum CurrentViewStatus {
    SourceWaiting,
    Pending {
        candidate_count: u64,
        automatic_source: bool,
    },
    Ready {
        cut: u64,
        value_count: u64,
        automatic_source: bool,
        attempted: u64,
    },
    Unavailable {
        attempted: Option<u64>,
        reason: String,
        automatic_source: bool,
    },
    Cancelled,
}

candidate_type!(
    /// An authenticated current view from an authorized holder. Adopt it with
    /// `adopt_current_view` before reading its objects from the durable inbox.
    CurrentViewCandidate
);

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CurrentViewAdoption {
    pub workspace: WorkspaceInfo,
    pub cut: u64,
    pub pending: u64,
    pub stale: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct RecoveryCutoffRequest {
    pub peer: EndpointId,
    pub revision: u64,
    pub topics: Vec<String>,
    pub epoch: Option<u64>,
}

#[non_exhaustive]
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum RecoveryCutoffStatus {
    Pending,
    Denied,
    Observed {
        workspace: WorkspaceId,
        author: MemberId,
        peer: EndpointId,
        epoch: u64,
        revision: u64,
        topics: Vec<String>,
        head: u64,
        retained_after: u64,
        accepted_through: u64,
    },
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl Client {
    /// The next direct stream gap. No progress is accepted by this read.
    pub fn next_direct_gap(&self) -> Result<Option<DirectRecoveryRequest>> {
        Ok(self
            .call(Op::NextDirectGap, ops_recovery::next_direct_gap)?
            .map(|gap| DirectRecoveryRequest {
                author: gap.author.into(),
                revision: gap.revision,
                topic: gap.topic,
                recipients: gap.recipients.into_iter().map(Into::into).collect(),
                after: gap.after,
                through: gap.through,
            }))
    }

    pub fn fetch_direct_recovery(
        &self,
        request: DirectRecoveryRequest,
    ) -> Result<DirectRecoveryStatus> {
        self.call(Op::FetchDirectRecovery, |session| {
            ops_recovery::fetch_direct(
                session,
                ops_recovery::FetchDirectArgs {
                    author: request.author.to_bytes(),
                    revision: request.revision,
                    topic: request.topic,
                    recipients: request
                        .recipients
                        .into_iter()
                        .map(MemberId::to_bytes)
                        .collect(),
                    after: request.after,
                    through: request.through,
                },
            )
        })
        .map(direct_status)
    }

    pub fn poll_direct_recovery(&self) -> Result<Option<DirectRecoveryStatus>> {
        self.call(Op::PollDirectRecovery, ops_recovery::poll_direct)
            .map(|status| status.map(direct_status))
    }

    pub fn cancel_direct_recovery(&self) -> Result<()> {
        self.call(Op::CancelDirectRecovery, ops_recovery::cancel_direct)?;
        Ok(())
    }

    pub fn stage_direct_recovery(&self) -> Result<RecoveryStage> {
        let staged = self.call(Op::StageDirectRecovery, ops_recovery::stage_direct)?;
        self.recovery_stage(staged)
    }

    /// Record an authenticated miss only after the recovery sources are exhausted.
    pub fn stage_direct_miss(&self) -> Result<Arc<RecoveryCandidate>> {
        let candidate = self.call(Op::StageDirectMiss, ops_recovery::stage_direct_miss)?;
        self.recovery_candidate(candidate)
    }

    /// Fetch the current catalog view from the author or an authorized holder.
    /// This uses the signed selector, replacement keys and expiry metadata.
    pub fn fetch_current_view(&self, request: CurrentViewRequest) -> Result<CurrentViewStatus> {
        self.call(Op::FetchCurrentView, |session| {
            ops_recovery::fetch_current_view(
                session,
                ops_recovery::FetchCurrentViewArgs {
                    peer: request.peer.map(EndpointId::to_bytes),
                    authority: request.authority.to_bytes(),
                    revision: request.revision,
                    topic: request.topic,
                    selector: request.selector.to_bytes(),
                },
            )
        })
        .map(current_status)
    }

    pub fn poll_current_view(&self) -> Result<Option<CurrentViewStatus>> {
        self.call(Op::PollCurrentView, ops_recovery::poll_current_view)
            .map(|status| status.map(current_status))
    }

    pub fn cancel_current_view(&self) -> Result<()> {
        self.call(Op::CancelCurrentView, ops_recovery::cancel_current_view)?;
        Ok(())
    }

    pub fn stage_current_view(&self) -> Result<Arc<CurrentViewCandidate>> {
        let staged = self.call(Op::StageCurrentView, ops_recovery::stage_current_view)?;
        Ok(CurrentViewCandidate::new(
            self.handle()?,
            staged.workspace,
            staged.snapshot,
        ))
    }

    pub fn adopt_current_view(
        &self,
        candidate: &CurrentViewCandidate,
    ) -> Result<CurrentViewAdoption> {
        let adopted = self
            .adopt(
                Op::AdoptCurrentView,
                &candidate.staged,
                &[CandidateKind::CurrentView],
            )?
            .adopted()?;
        let counts = adopted
            .current_view
            .ok_or_else(|| ApiError::wrong_state("candidate has no current view"))?;
        Ok(CurrentViewAdoption {
            workspace: workspace_info(adopted),
            cut: counts.cut,
            pending: counts.pending as u64,
            stale: counts.stale as u64,
        })
    }

    pub fn discover_recovery_cutoff(
        &self,
        request: RecoveryCutoffRequest,
    ) -> Result<RecoveryCutoffStatus> {
        self.call(Op::DiscoverRecoveryCutoff, |session| {
            ops_recovery::discover_cutoff(
                session,
                ops_recovery::CutoffArgs {
                    peer: request.peer.to_bytes(),
                    revision: request.revision,
                    topics: request.topics,
                    epoch: request.epoch,
                },
            )
        })
        .map(cutoff_status)
    }

    pub fn poll_recovery_cutoff(&self) -> Result<Option<RecoveryCutoffStatus>> {
        self.call(Op::PollRecoveryCutoff, ops_recovery::poll_cutoff)
            .map(|status| status.map(cutoff_status))
    }
}

impl Client {
    fn recovery_candidate(
        &self,
        candidate: ops_recovery::StagedRecovery,
    ) -> Result<Arc<RecoveryCandidate>> {
        Ok(Arc::new(RecoveryCandidate {
            candidate: ProtectedReceptionCandidate::new(
                self.handle()?,
                candidate.workspace,
                candidate.snapshot,
            ),
            publication_count: candidate.publication_count.unwrap_or(0) as u64,
        }))
    }

    pub(super) fn recovery_stage(
        &self,
        staged: ops_recovery::RecoveryStaged,
    ) -> Result<RecoveryStage> {
        match staged {
            ops_recovery::RecoveryStaged::Candidate(candidate) => self
                .recovery_candidate(candidate)
                .map(RecoveryStage::Candidate),
            ops_recovery::RecoveryStaged::Nothing(nothing) => match nothing.state {
                "recovery_already_covered" | "direct_recovery_already_covered" => {
                    Ok(RecoveryStage::AlreadyCovered)
                }
                "recovery_no_new_objects" => Ok(RecoveryStage::NoNewObjects),
                "recovery_awaiting_application" | "direct_recovery_awaiting_application" => {
                    Ok(RecoveryStage::AwaitingApplication)
                }
                _ => Err(ApiError::wrong_state("unknown recovery stage")),
            },
        }
    }
}

fn direct_status(value: ops_recovery::DirectStatus) -> DirectRecoveryStatus {
    use ops_recovery::DirectStatus as S;
    match value {
        S::DirectRecoverySourceWaiting { .. } => DirectRecoveryStatus::SourceWaiting,
        S::DirectRecoveryPending {
            candidate_count, ..
        } => DirectRecoveryStatus::Pending {
            candidate_count: candidate_count as u64,
        },
        S::DirectRecoveryCancelled { .. } => DirectRecoveryStatus::Cancelled,
        S::DirectRecoverySourceUnavailable {
            attempted, reason, ..
        } => DirectRecoveryStatus::SourceUnavailable {
            attempted: attempted as u64,
            reason,
        },
        S::DirectRecoveryReady {
            workspace,
            author,
            peer,
            epoch,
            revision,
            topic,
            after,
            through,
            packet_count,
            retained_bytes,
            attempted,
            ..
        } => DirectRecoveryStatus::Ready {
            range: DirectRecoveryReady {
                workspace: workspace.into(),
                author: author.into(),
                peer: peer.into(),
                epoch,
                revision,
                topic,
                after,
                through,
                packet_count: packet_count as u64,
                retained_bytes: retained_bytes as u64,
                attempted: attempted as u64,
            },
        },
    }
}

fn current_status(value: ops_recovery::CurrentViewStatus) -> CurrentViewStatus {
    use ops_recovery::CurrentViewStatus as S;
    match value {
        S::CurrentViewSourceWaiting { .. } => CurrentViewStatus::SourceWaiting,
        S::CurrentViewPending {
            candidate_count,
            automatic_source,
            ..
        } => CurrentViewStatus::Pending {
            candidate_count: candidate_count as u64,
            automatic_source,
        },
        S::CurrentViewCancelled { .. } => CurrentViewStatus::Cancelled,
        S::CurrentViewReady {
            cut,
            value_count,
            automatic_source,
            attempted,
            ..
        } => CurrentViewStatus::Ready {
            cut,
            value_count: value_count as u64,
            automatic_source,
            attempted: attempted as u64,
        },
        S::CurrentViewUnavailable {
            attempted,
            reason,
            automatic_source,
            ..
        } => CurrentViewStatus::Unavailable {
            attempted: attempted.map(|n| n as u64),
            reason,
            automatic_source,
        },
    }
}

fn cutoff_status(value: ops_recovery::CutoffStatus) -> RecoveryCutoffStatus {
    use ops_recovery::CutoffStatus as S;
    match value {
        S::RecoveryCutoffPending { .. } => RecoveryCutoffStatus::Pending,
        S::RecoveryCutoffDenied { .. } => RecoveryCutoffStatus::Denied,
        S::RecoveryCutoffObserved {
            workspace,
            author,
            peer,
            epoch,
            revision,
            topics,
            head,
            retained_after,
            accepted_through,
            ..
        } => RecoveryCutoffStatus::Observed {
            workspace: workspace.into(),
            author: author.into(),
            peer: peer.into(),
            epoch,
            revision,
            topics,
            head,
            retained_after,
            accepted_through,
        },
    }
}
