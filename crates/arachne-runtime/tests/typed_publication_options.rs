//! Publication options use the same typed surface as generated bindings.
use arachne_runtime::*;
use std::{
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const TOPIC: &str = "objects/options";

struct Group {
    nodes: [Arc<Client>; 3],
    workspace: WorkspaceId,
    revision: u64,
    members: [MemberId; 3],
}

fn connect(from: &Client, to: &Client) {
    let info = to.endpoint().unwrap();
    let address: std::net::SocketAddr = info.bound_address.parse().unwrap();
    from.add_address_hint(info.endpoint_key, &format!("127.0.0.1:{}", address.port()))
        .unwrap();
}

fn join(owner: &Arc<Client>, reader: &Arc<Client>, invite: &InvitationInfo) {
    let begin = reader
        .begin_join(&invite.invitation, &invite.checkpoint, "Reader")
        .unwrap();
    let staged = owner
        .stage_admission(begin.endpoint, &begin.admission_request)
        .unwrap();
    owner.adopt_admission(&staged).unwrap();
    let grant = std::thread::scope(|scope| {
        let job = scope.spawn(|| reader.request_admission(invite.peer).unwrap());
        let end = Instant::now() + Duration::from_secs(10);
        while !job.is_finished() {
            owner.poll_control().unwrap();
            assert!(Instant::now() < end);
            std::thread::sleep(Duration::from_millis(2));
        }
        match job.join().unwrap() {
            AdmissionResponse::Granted { grant } => grant,
            other => panic!("unexpected admission: {other:?}"),
        }
    });
    reader
        .adopt_join(&reader.stage_join_grant(&grant).unwrap())
        .unwrap();
}

impl Group {
    fn new(seed: u8) -> Self {
        let context = Context::owned(Default::default(), Default::default(), 2).unwrap();
        let nodes = std::array::from_fn(|index| {
            Client::open_in(
                context.clone(),
                ClientConfig {
                    network: Network::Direct,
                    secret: Some([seed + index as u8; 32].into()),
                    transport: TransportOptions {
                        deadline: Some(Duration::from_secs(3)),
                        ..Default::default()
                    },
                    storage: Some(StorageConfig::memory(&MemoryProvider::default()).into()),
                },
            )
            .unwrap()
        });
        for from in &nodes {
            for to in &nodes {
                if !Arc::ptr_eq(from, to) {
                    connect(from, to);
                }
            }
        }
        let [owner, reader, bystander] = &nodes;
        let workspace = owner.create_workspace("Owner", None).unwrap().workspace;
        let invitation = owner
            .adopt_invitation(&owner.stage_invitation(0).unwrap())
            .unwrap();
        join(owner, reader, &invitation);
        join(owner, bystander, &invitation);
        reader
            .fetch_membership_update(owner.endpoint().unwrap().endpoint_key, false)
            .unwrap();
        let end = Instant::now() + Duration::from_secs(10);
        let update = loop {
            owner.poll_control().unwrap();
            if let Some(update) = reader.poll_membership_update().unwrap() {
                break update;
            }
            assert!(Instant::now() < end);
            std::thread::sleep(Duration::from_millis(2));
        };
        match reader.stage_membership_update(&update).unwrap() {
            MembershipCandidate::Workspace { candidate } => {
                reader.adopt_admission(&candidate).unwrap();
            }
            other => panic!("unexpected update: {other:?}"),
        }
        let revision = owner.member_roster().unwrap().epoch + 1;
        for client in &nodes {
            client.install_workspace_policy(revision).unwrap();
        }
        let members = std::array::from_fn(|index| {
            nodes[index]
                .member_roster()
                .unwrap()
                .members
                .into_iter()
                .find(|member| member.self_member)
                .unwrap()
                .id
        });
        for subscriber in [&nodes[1], &nodes[2]] {
            subscriber
                .set_interest(workspace, revision, TOPIC, true)
                .unwrap();
            loop {
                for client in &nodes {
                    client.poll_control().unwrap();
                }
                if let Some(interest) = subscriber.poll_interest().unwrap() {
                    assert!(interest.admission.failed.is_empty(), "{interest:?}");
                    break;
                }
                assert!(Instant::now() < end, "interest did not settle");
                std::thread::sleep(Duration::from_millis(2));
            }
        }
        Self {
            nodes,
            workspace,
            revision,
            members,
        }
    }

    fn receive(&self, index: usize) -> ReceivedProtectedPublication {
        let client = &self.nodes[index];
        let end = Instant::now() + Duration::from_secs(10);
        loop {
            for peer in &self.nodes {
                peer.poll_control().unwrap();
            }
            if let Some(candidate) = client.poll_protected().unwrap() {
                client.adopt_protected_reception(&candidate).unwrap();
            }
            if let Some(object) = client.poll_pending_object().unwrap() {
                client
                    .adopt_protected_reception(
                        &client.stage_object_acknowledgement(&object).unwrap(),
                    )
                    .unwrap();
                return object;
            }
            assert!(
                Instant::now() < end,
                "protected object did not arrive at node {index}"
            );
            std::thread::sleep(Duration::from_millis(2));
        }
    }
}

impl Drop for Group {
    fn drop(&mut self) {
        for client in &self.nodes {
            let _ = client.close();
        }
    }
}

fn current() -> PublicationCurrent {
    PublicationCurrent {
        selector: [9; 32].into(),
        replacement_key: [10; 32].into(),
        expires_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600,
        tombstone: false,
    }
}

#[test]
fn addressed_critical_and_bulk_exclude_an_interested_bystander() {
    let group = Group::new(61);
    let owner = &group.nodes[0];
    for (index, mode) in [PublicationMode::Critical, PublicationMode::Bulk]
        .into_iter()
        .enumerate()
    {
        let payload = vec![index as u8, 41, 42];
        let staged = owner
            .stage_protected_publication_with_options(
                group.workspace,
                group.revision,
                TOPIC,
                [index as u8 + 1; 16].into(),
                payload.clone(),
                PublicationOptions {
                    recipients: vec![group.members[1]],
                    mode,
                },
            )
            .unwrap();
        let sent = owner.adopt_protected_publication(&staged).unwrap();
        assert_eq!(
            sent.admitted,
            vec![group.nodes[1].endpoint().unwrap().endpoint_key]
        );
        assert!(sent.failed.is_empty());
        let received = group.receive(1);
        assert_eq!(received.payload, payload);
        assert_eq!(received.recipients, vec![group.members[1]]);
        assert!(group.nodes[2].poll_protected().unwrap().is_none());
        assert!(group.nodes[2].poll_pending_object().unwrap().is_none());
    }
    // A group control proves that the bystander is reachable and subscribed.
    let control = owner
        .stage_protected_publication(
            group.workspace,
            group.revision,
            TOPIC,
            [3; 16].into(),
            b"group control".to_vec(),
        )
        .unwrap();
    owner.adopt_protected_publication(&control).unwrap();
    for index in [1, 2] {
        let received = group.receive(index);
        assert_eq!(received.payload, b"group control");
        assert!(received.recipients.is_empty());
    }
}

#[test]
fn invalid_audiences_and_current_conflicts_are_rejected_before_staging() {
    let group = Group::new(71);
    let owner = &group.nodes[0];
    let mut unsorted = vec![group.members[1], group.members[2]];
    unsorted.sort_unstable_by(|a, b| b.cmp(a));
    let invalid = [
        (
            "unknown",
            vec![MemberId::from_bytes([0; 32])],
            ErrorCode::NotMember,
        ),
        ("self", vec![group.members[0]], ErrorCode::InvalidInput),
        (
            "duplicate",
            vec![group.members[1], group.members[1]],
            ErrorCode::InvalidInput,
        ),
        ("unsorted", unsorted, ErrorCode::InvalidInput),
        (
            "oversized",
            (0..65)
                .map(|value| MemberId::from_bytes([value; 32]))
                .collect(),
            ErrorCode::InvalidInput,
        ),
    ];
    assert_eq!(
        MemberId::from_slice(&[1; 31]).unwrap_err().code(),
        ErrorCode::InvalidId
    );
    for (case, recipients, expected) in invalid {
        let result = owner.stage_protected_publication_with_options(
            group.workspace,
            group.revision,
            TOPIC,
            [4; 16].into(),
            vec![4],
            PublicationOptions {
                recipients,
                mode: PublicationMode::Critical,
            },
        );
        assert_eq!(result.unwrap_err().code(), expected, "{case}");
    }
    let result = owner.stage_protected_publication_with_options(
        group.workspace,
        group.revision,
        TOPIC,
        [4; 16].into(),
        vec![4],
        PublicationOptions {
            recipients: vec![group.members[1]],
            mode: PublicationMode::Current {
                metadata: current(),
            },
        },
    );
    assert_eq!(result.unwrap_err().code(), ErrorCode::InvalidInput);
    let mut recipients = vec![group.members[1], group.members[2]];
    recipients.sort_unstable();
    let valid = owner
        .stage_protected_publication_with_options(
            group.workspace,
            group.revision,
            TOPIC,
            [4; 16].into(),
            vec![4],
            PublicationOptions {
                recipients: recipients.clone(),
                mode: PublicationMode::Bulk,
            },
        )
        .unwrap();
    let sent = owner.adopt_protected_publication(&valid).unwrap();
    assert!(sent.failed.is_empty(), "{sent:?}");
    assert_eq!(sent.admitted.len(), 2, "{sent:?}");
    for index in [1, 2] {
        assert_eq!(group.receive(index).recipients, recipients);
    }
}

#[test]
fn current_options_and_existing_defaults_keep_group_semantics() {
    let group = Group::new(81);
    assert_eq!(default_publication_options(), PublicationOptions::default());
    assert!(default_publication_options().recipients.is_empty());
    assert_eq!(
        default_publication_options().mode,
        PublicationMode::Critical
    );
    let owner = &group.nodes[0];
    let metadata = current();
    for index in 0..3 {
        let id = [index + 5; 16].into();
        let payload = vec![index + 5];
        let candidate = match index {
            0 => owner.stage_protected_publication_with_current(
                group.workspace,
                group.revision,
                TOPIC,
                id,
                payload.clone(),
                None,
            ),
            1 => owner.stage_protected_publication_with_current(
                group.workspace,
                group.revision,
                TOPIC,
                id,
                payload.clone(),
                Some(metadata),
            ),
            _ => owner.stage_protected_publication_with_options(
                group.workspace,
                group.revision,
                TOPIC,
                id,
                payload.clone(),
                PublicationOptions {
                    recipients: vec![],
                    mode: PublicationMode::Current { metadata },
                },
            ),
        }
        .unwrap();
        owner.adopt_protected_publication(&candidate).unwrap();
        for peer in [1, 2] {
            let received = group.receive(peer);
            assert_eq!(received.payload, payload);
            assert!(received.recipients.is_empty());
            assert_eq!(
                received.current,
                if index == 0 { None } else { Some(metadata) }
            );
        }
    }
}
