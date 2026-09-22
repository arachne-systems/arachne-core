use arachne_runtime::{
    Client, ClientConfig, ErrorKind, JoinAdmissionStep, MemberKind, Network, PeerPolicy, Presence,
    RecoveredPublication, RecoveryRangeRequest, RecoveryRangeStatus, WorkspacePhase,
};
use std::time::{Duration, Instant};

#[test]
fn typed_client_reports_endpoint_and_workspace_state_then_closes() {
    let mut client = Client::open(ClientConfig {
        network: Network::Direct,
        secret: Some([7; 32]),
    })
    .unwrap();

    let endpoint = client.endpoint().unwrap();
    assert_eq!(
        endpoint.endpoint_key,
        client.workspace_state().unwrap().endpoint_key
    );
    assert!(!endpoint.bound_address.is_empty());

    let state = client.workspace_state().unwrap();
    assert_eq!(state.phase, WorkspacePhase::Empty);
    assert!(!state.workspace_ready);
    assert!(!state.durable);

    client.cancel().unwrap();
    client.close().unwrap();
    let error = client.close().unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Closed);
}

#[test]
fn typed_client_creates_named_workspace_with_typed_state() {
    let mut client = Client::open(ClientConfig {
        network: Network::Direct,
        secret: Some([10; 32]),
    })
    .unwrap();

    let workspace = client
        .create_workspace("Owner", Some("Field Team"))
        .unwrap();
    assert_eq!(workspace.workspace_name.as_deref(), Some("Field Team"));
    assert_eq!(workspace.member_count, 1);
    assert_eq!(workspace.epoch, 0);
    assert!(!workspace.durable);
    assert_eq!(
        client.workspace_state().unwrap().phase,
        WorkspacePhase::Active
    );

    client.close().unwrap();
}

#[test]
fn typed_client_exposes_recovery_result_without_vendor_types() {
    let mut client = Client::open(ClientConfig {
        network: Network::Direct,
        secret: Some([11; 32]),
    })
    .unwrap();
    client.create_workspace("Owner", None).unwrap();

    let recovered: Option<RecoveredPublication> = client.poll_recovered_publication().unwrap();
    assert!(recovered.is_none());
    client.close().unwrap();
}

#[test]
fn typed_client_exposes_recovery_request_lifecycle() {
    let mut client = Client::open(ClientConfig {
        network: Network::Direct,
        secret: Some([15; 32]),
    })
    .unwrap();
    let workspace = client.create_workspace("Owner", None).unwrap();
    let member = client.member_roster().unwrap().members[0].id;

    assert_eq!(
        client
            .fetch_recovery_range(RecoveryRangeRequest {
                peer: None,
                author: Some(member),
                revision: workspace.epoch,
                topics: vec!["streams/example".into()],
                after: Some(0),
                through: Some(1),
            })
            .unwrap(),
        RecoveryRangeStatus::SourceWaiting {
            automatic_source: true,
        }
    );
    assert!(client.poll_recovery_range().unwrap().is_none());
    client.cancel_recovery_range().unwrap();
    client.close().unwrap();
}

#[test]
fn typed_clients_recover_an_opaque_publication() {
    let mut owner = Client::open(ClientConfig {
        network: Network::Direct,
        secret: Some([16; 32]),
    })
    .unwrap();
    let mut reader = Client::open(ClientConfig {
        network: Network::Direct,
        secret: Some([17; 32]),
    })
    .unwrap();
    let workspace = owner
        .create_workspace("Owner", Some("Recovery proof"))
        .unwrap();
    let invitation = owner.issue_invitation().unwrap();
    let owner_address = invitation.address.replace("0.0.0.0:", "127.0.0.1:");
    reader
        .add_address_hint(invitation.peer, &owner_address)
        .unwrap();

    let join = reader
        .begin_join(&invitation.invitation, &invitation.checkpoint, "Reader")
        .unwrap();
    let staged = owner
        .stage_admission(join.endpoint, &join.admission_request)
        .unwrap();
    let joined_owner = owner.adopt_admission(&staged.snapshot).unwrap();
    let reply = owner
        .retained_admission(join.endpoint, &join.admission_request)
        .unwrap();
    let staged = reader
        .stage_join(
            &reply.welcome,
            &[JoinAdmissionStep {
                commit: reply.commit,
                authorization: reply.authorization,
            }],
        )
        .unwrap();
    let joined_reader = reader.adopt_join(&staged.snapshot).unwrap();
    assert_eq!(joined_owner.epoch, joined_reader.epoch);
    let revision = joined_owner.epoch + 1;
    owner.install_workspace_policy(revision).unwrap();
    reader.install_workspace_policy(revision).unwrap();

    let payload = vec![0, 255, 42, 7];
    let staged = owner
        .stage_protected_publication(
            workspace.workspace,
            revision,
            "streams/example",
            [7; 16],
            payload.clone(),
        )
        .unwrap();
    owner.adopt_protected_publication(&staged.snapshot).unwrap();

    let owner_endpoint = owner.endpoint().unwrap();
    let owner_member = owner
        .member_roster()
        .unwrap()
        .members
        .into_iter()
        .find(|member| member.self_member)
        .unwrap()
        .id;
    let initial = reader
        .fetch_recovery_range(RecoveryRangeRequest {
            peer: Some(owner_endpoint.endpoint_key),
            author: Some(owner_member),
            revision,
            topics: vec!["streams/example".into()],
            after: Some(0),
            through: Some(1),
        })
        .unwrap();
    assert!(matches!(
        initial,
        RecoveryRangeStatus::Pending { .. } | RecoveryRangeStatus::Ready(_)
    ));

    let deadline = Instant::now() + Duration::from_secs(10);
    let ready = loop {
        owner.poll_control().unwrap();
        if let Some(status) = reader.poll_recovery_range().unwrap() {
            break match status {
                RecoveryRangeStatus::Ready(ready) => ready,
                other => panic!("unexpected recovery status: {other:?}"),
            };
        }
        assert!(Instant::now() < deadline, "typed recovery did not complete");
        std::thread::sleep(Duration::from_millis(5));
    };
    assert_eq!(ready.packet_count, 1);

    let staged = match reader.stage_recovery_range(0).unwrap() {
        arachne_runtime::RecoveryStage::Candidate(candidate) => candidate,
        other => panic!("unexpected recovery stage: {other:?}"),
    };
    assert_eq!(staged.publication_count, 1);
    let adoption = reader.adopt_recovery(&staged.snapshot).unwrap();
    assert_eq!(adoption.recovered_publications, 1);

    let recovered = loop {
        if let Some(publication) = reader.poll_recovered_publication().unwrap() {
            break publication;
        }
        assert!(
            Instant::now() < deadline,
            "typed recovery publication did not arrive"
        );
        std::thread::sleep(Duration::from_millis(5));
    };
    assert_eq!(recovered.workspace, workspace.workspace);
    assert_eq!(recovered.topic, "streams/example");
    assert_eq!(recovered.payload, payload);

    reader.close().unwrap();
    owner.close().unwrap();
}

#[test]
fn typed_client_exposes_workspace_roster_and_profile_projection() {
    let mut client = Client::open(ClientConfig {
        network: Network::Direct,
        secret: Some([12; 32]),
    })
    .unwrap();
    let workspace = client.create_workspace("Owner", None).unwrap();

    let roster = client.member_roster().unwrap();
    assert_eq!(roster.workspace, workspace.workspace);
    assert_eq!(roster.epoch, 0);
    assert_eq!(roster.members.len(), 1);
    assert_eq!(roster.members[0].display_name.as_deref(), Some("Owner"));
    assert!(roster.members[0].self_member);
    assert_eq!(roster.members[0].kind, MemberKind::Person);
    assert_eq!(roster.members[0].presence, Presence::SelfMember);
    client.close().unwrap();
}

#[test]
fn typed_client_issues_an_invitation_with_bounded_route_hints() {
    let mut client = Client::open(ClientConfig {
        network: Network::Direct,
        secret: Some([13; 32]),
    })
    .unwrap();
    let workspace = client
        .create_workspace("Owner", Some("Field Team"))
        .unwrap();

    let invitation = client.issue_invitation().unwrap();
    assert_eq!(invitation.workspace, workspace.workspace);
    assert_eq!(invitation.workspace_name.as_deref(), Some("Field Team"));
    assert!(!invitation.invitation.is_empty());
    assert!(!invitation.checkpoint.is_empty());
    assert!(invitation.bootstrap_peers.len() <= 3);
    assert!(invitation.routes.len() <= 7);
    let inspected = client
        .inspect_invitation(&invitation.invitation, &invitation.checkpoint)
        .unwrap();
    assert_eq!(inspected.workspace, workspace.workspace);
    assert_eq!(inspected.workspace_name.as_deref(), Some("Field Team"));
    assert_eq!(inspected.epoch, 0);
    client.close().unwrap();
}

#[test]
fn typed_client_reports_connectivity_without_exposing_transport_types() {
    let mut client = Client::open(ClientConfig {
        network: Network::Direct,
        secret: Some([14; 32]),
    })
    .unwrap();
    let workspace = client.create_workspace("Owner", None).unwrap();

    let connectivity = client.connectivity().unwrap();
    assert_eq!(connectivity.workspace, workspace.workspace);
    assert!(connectivity.paths.is_empty());
    assert!(!connectivity.paths_limited);

    let metrics = client.metrics().unwrap();
    assert_eq!(metrics.workspace, workspace.workspace);
    assert_eq!(metrics.phase, arachne_runtime::WorkspacePhase::Active);
    assert_eq!(metrics.received_bytes, 0);
    assert_eq!(metrics.sent_bytes, 0);
    assert_eq!(metrics.membership_gossip.sent, 0);
    assert_eq!(metrics.control_timing.inquiry.count, 0);
    assert!(metrics.paths.is_empty());
    client.network_change().unwrap();
    client.close().unwrap();
}

#[test]
fn typed_client_routes_opaque_publication_and_reports_interest() {
    let mut publisher = Client::open(ClientConfig {
        network: Network::Direct,
        secret: Some([8; 32]),
    })
    .unwrap();
    let mut subscriber = Client::open(ClientConfig {
        network: Network::Direct,
        secret: Some([9; 32]),
    })
    .unwrap();
    let publisher_endpoint = publisher.endpoint().unwrap();
    let subscriber_endpoint = subscriber.endpoint().unwrap();
    let workspace = [82; 32];
    let policy = [
        PeerPolicy {
            peer: publisher_endpoint.endpoint_key,
            publish: vec!["streams/live".into()],
            subscribe: Vec::new(),
        },
        PeerPolicy {
            peer: subscriber_endpoint.endpoint_key,
            publish: Vec::new(),
            subscribe: vec!["streams/live".into()],
        },
    ];

    publisher
        .add_address_hint(
            subscriber_endpoint.endpoint_key,
            &subscriber_endpoint
                .bound_address
                .replace("0.0.0.0:", "127.0.0.1:"),
        )
        .unwrap();
    subscriber
        .add_address_hint(
            publisher_endpoint.endpoint_key,
            &publisher_endpoint
                .bound_address
                .replace("0.0.0.0:", "127.0.0.1:"),
        )
        .unwrap();
    publisher.install_policy(workspace, 1, &policy).unwrap();
    subscriber.install_policy(workspace, 1, &policy).unwrap();
    subscriber
        .set_interest(workspace, 1, "streams/live", true)
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        if let Some(observation) = subscriber.poll_interest().unwrap() {
            assert!(observation.admission.failed.is_empty(), "{observation:?}");
            break;
        }
        assert!(Instant::now() < deadline, "interest did not settle");
        std::thread::sleep(Duration::from_millis(10));
    }

    let report = publisher
        .publish(workspace, 1, "streams/live", vec![7])
        .unwrap();
    assert_eq!(report.admitted, vec![subscriber_endpoint.endpoint_key]);

    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        if let Some(publication) = subscriber.poll().unwrap() {
            assert_eq!(publication.workspace, workspace);
            assert_eq!(publication.topic, "streams/live");
            assert_eq!(publication.payload, vec![7]);
            break;
        }
        assert!(Instant::now() < deadline, "publication did not arrive");
        std::thread::sleep(Duration::from_millis(10));
    }

    subscriber.close().unwrap();
    publisher.close().unwrap();
}
