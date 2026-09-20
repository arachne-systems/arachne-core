//! The committed view: one workspace's state as of its latest adopted
//! transition, shared read-only. Inquiries are answered from it without the
//! host, the session lock or the control queue. It is replaced, never edited:
//! a transition works on a provisional copy and publishes a new view only
//! after that copy is saved and adopted. An answer therefore never shows
//! state that a restart could lose.
use super::*;
use std::sync::RwLock;

pub(super) struct CommittedView {
    workspace: Arc<arachne_security::Workspace>,
    /// This member's own endpoint, as the facilitator named in checkpoint proofs.
    endpoint: [u8; 32],
}

/// The published view of one session. `None` until a workspace is committed.
/// It also carries the session's retained member profiles: a membership
/// query reads and extends them without the host (ADR 0010).
#[derive(Clone, Default)]
pub(super) struct Published {
    view: Arc<RwLock<Option<Arc<CommittedView>>>>,
    profiles: membership::Profiles,
    /// Wakes the host to gossip names and hear of answered queries.
    signal: Option<Arc<work_signal::WorkSignal>>,
}

impl Published {
    pub(super) fn new(signal: Option<Arc<work_signal::WorkSignal>>) -> Self {
        Self {
            signal,
            ..Self::default()
        }
    }

    /// The profile set the session shares with the responder.
    pub(super) fn profiles(&self) -> membership::Profiles {
        Arc::clone(&self.profiles)
    }

    pub(super) fn publish(&self, workspace: Arc<arachne_security::Workspace>, endpoint: [u8; 32]) {
        *self.view.write().unwrap_or_else(|error| error.into_inner()) =
            Some(Arc::new(CommittedView {
                workspace,
                endpoint,
            }));
    }

    pub(super) fn clear(&self) {
        *self.view.write().unwrap_or_else(|error| error.into_inner()) = None;
        *self.profiles.lock().unwrap_or_else(|error| error.into_inner()) = Default::default();
    }

    fn current(&self) -> Option<Arc<CommittedView>> {
        self.view
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
    }

    /// The responder the node calls before the host queue. `None` means the
    /// request is not an inquiry, or there is no committed workspace yet, and
    /// the host handles it exactly as before.
    pub(super) fn responder(&self) -> arachne_node::InquiryResponder {
        let published = self.clone();
        Arc::new(move |peer, payload| {
            let view = published.current()?;
            if payload.starts_with(b"DFMQ") {
                return published.answer_membership_query(&view, peer, payload);
            }
            if payload.starts_with(membership::PROFILE_QUERY_PREFIX) {
                let set = membership::lock_profiles(&published.profiles);
                return Some(membership::profile_page_reply(
                    Some(&view.workspace),
                    &set,
                    peer,
                    payload,
                ));
            }
            view.answer(peer, payload)
        })
    }

    /// A membership query also carries the querier's signed names. They are
    /// verified against the committed roster and retained in the shared set
    /// before the answer is built, as on the host path, so the digest and the
    /// page in the answer include them. Only gossip of new names and the
    /// host's notice wait for the host.
    fn answer_membership_query(
        &self,
        view: &CommittedView,
        peer: [u8; 32],
        payload: &[u8],
    ) -> Option<Vec<u8>> {
        let mut set = membership::lock_profiles(&self.profiles);
        let reply = membership::answer_query(
            Some(&view.workspace),
            &mut set,
            peer,
            payload,
            membership::MAX_PROFILE_SET_BYTES,
        );
        // Unencodable (a step over the reply bound): the host path reports
        // the error as before. The retained names stay; merging is idempotent.
        let bytes = membership::encode_reply(&reply).ok()?;
        let current = reply["state"] != "membership_denied"
            && view.workspace.member_id_for_endpoint(peer).is_ok();
        set.note_answered(current.then_some(peer));
        drop(set);
        if let Some(signal) = &self.signal {
            signal.raise();
        }
        Some(bytes)
    }
}

const UNAVAILABLE: &[u8] = b"{\"state\":\"admission_unavailable\",\"reason\":\"unavailable\"}";

impl CommittedView {
    /// Each arm gives the same bytes the host path gives for the same request
    /// and state. Authorization stays inside the workspace calls: the peer is
    /// the authenticated transport identity, never a field of the payload.
    fn answer(&self, peer: [u8; 32], payload: &[u8]) -> Option<Vec<u8>> {
        if payload.starts_with(INVITATION_CHECKPOINT_REQUEST) {
            let proof = &payload[INVITATION_CHECKPOINT_REQUEST.len()..];
            return Some(
                self.workspace
                    .checkpoint_for_invitation(peer, self.endpoint, proof)
                    .unwrap_or_default(),
            );
        }
        if payload.starts_with(ADMISSION_HISTORY_PAGE_REQUEST) {
            let page = parse_admission_history_page_packet(payload).ok().and_then(
                |(request, checkpoint, offset)| {
                    admission_reply_page(&self.workspace, peer, request, Some(checkpoint), offset)
                        .ok()
                },
            );
            return Some(page.unwrap_or_else(|| UNAVAILABLE.to_vec()));
        }
        // A range pull reads committed steps only (ADR 0009).
        if payload.starts_with(b"DFMS") {
            return Some(membership::range_reply(
                Some(&self.workspace),
                peer,
                payload,
            ));
        }
        // A join request is an inquiry only when its result is already
        // retained. Otherwise it asks for a membership change: host queue.
        if payload.starts_with(b"DFJA") {
            let (request, checkpoint, _) = admission_packet(payload).ok()?;
            self.workspace.retained_admission(peer, request).ok()??;
            return admission_reply_page(&self.workspace, peer, request, checkpoint, 0).ok();
        }
        None
    }
}

/// The same membership queries, answered by the host path on one session and
/// by the committed view on another built from the same committed workspace:
/// each reply is the same bytes, and both sessions retain the same names.
#[test]
fn a_membership_query_answer_is_the_host_answer() {
    let (owner, members, endpoints) = membership::admit_members(21, "Equal member", 3);
    let owner = Arc::new(owner);
    let mut host = membership::bare_test_session(owner.clone());
    let mut view = membership::bare_test_session(owner.clone());
    view.committed.publish(owner.clone(), view.node.id());
    let responder = view.committed.responder();
    let profiles: Vec<Vec<u8>> = members
        .iter()
        .map(|member| member.sign_member_profile().unwrap())
        .collect();
    let basis = membership::StateBasis::new(owner.epoch(), owner.epoch_fingerprint(), [0; 32]);
    let query = |digest: [u8; 32], carried: [&[u8]; 2]| {
        membership::wire::encode_query(&membership::wire::Query {
            workspace: owner.id(),
            basis,
            profiles_digest: digest,
            profiles: carried,
        })
        .unwrap()
    };
    let mut asks = vec![
        (endpoints[0], query([0; 32], [&profiles[0], &[]])),
        (endpoints[1], query([0; 32], [&profiles[1], &profiles[0]])),
        (endpoints[2], query([0; 32], [&profiles[2], &[]])),
        (endpoints[0], query([0; 32], [&[], &[]])),
        // Not a member: denied on both paths.
        ([250; 32], query([0; 32], [&[], &[]])),
    ];
    // A querier whose digest already matches gets no profile page.
    let mut probe = membership::bare_test_session(owner.clone());
    for (peer, bytes) in &asks[..3] {
        membership::reply_with_profiles(&mut probe, *peer, bytes);
    }
    let settled = membership::reply_with_profiles(&mut probe, endpoints[1], &asks[3].1);
    let digest: [u8; 32] = serde_json::from_value(settled["profiles_digest"].clone()).unwrap();
    asks.push((endpoints[1], query(digest, [&[], &[]])));
    for (peer, bytes) in asks {
        let expected =
            membership::encode_reply(&membership::reply_with_profiles(&mut host, peer, &bytes))
                .unwrap();
        let answered = responder(peer, &bytes).expect("a membership query is an inquiry");
        assert_eq!(
            answered,
            expected,
            "reply differs for peer {:?}",
            &peer[..2]
        );
    }
    assert_eq!(
        membership::roster(&mut view, &[]).unwrap(),
        membership::roster(&mut host, &[]).unwrap(),
        "the view retained different names than the host"
    );
    // A page of names is a pure read: the view gives the host's bytes.
    let page = membership::wire::encode_profile_query(&membership::wire::ProfileQuery {
        workspace: owner.id(),
        after: None,
    })
    .unwrap();
    let host_page = membership::profile_page_reply(
        host.workspace.as_deref(),
        &membership::lock_profiles(&host.profiles),
        endpoints[0],
        &page,
    );
    assert_eq!(responder(endpoints[0], &page), Some(host_page));
}
