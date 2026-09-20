use arachne_runtime::{
    Client, ClientConfig, ErrorKind, MemberKind, Network, PeerPolicy, Presence,
    RecoveredPublication, WorkspacePhase,
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
