use arachne_runtime::{
    Client, ClientConfig, ErrorCode, JoinAdmissionStep, MemberKind, MemoryProvider, Network,
    PeerPolicy, Presence, ReceivedProtectedPublication, RecoveryRangeRequest, RecoveryRangeStatus,
    StorageConfig, WorkspacePhase,
};
use std::time::{Duration, Instant};

#[test]
fn typed_client_reports_endpoint_and_workspace_state_then_closes() {
    let mut client = Client::open(ClientConfig {
        network: Network::Direct,
        secret: Some(([7; 32]).into()),
        transport: Default::default(),
        storage: None,
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
    // Close is idempotent (ADR step 4); other calls report Closed.
    client.close().unwrap();
    let error = client.endpoint().unwrap_err();
    assert_eq!(error.code(), ErrorCode::Closed);
}

#[test]
fn typed_client_creates_named_workspace_with_typed_state() {
    let provider = MemoryProvider::default();
    let mut client = Client::open(ClientConfig {
        network: Network::Direct,
        secret: Some(([10; 32]).into()),
        transport: Default::default(),
        storage: Some((StorageConfig::memory(&provider)).into()),
    })
    .unwrap();

    let workspace = client
        .create_workspace("Owner", Some("Field Team".into()))
        .unwrap();
    assert_eq!(workspace.workspace_name.as_deref(), Some("Field Team"));
    assert_eq!(workspace.member_count, 1);
    assert_eq!(workspace.epoch, 0);
    assert!(workspace.durable);
    assert_eq!(
        client.workspace_state().unwrap().phase,
        WorkspacePhase::Active
    );

    client.close().unwrap();
}

#[test]
fn typed_client_exposes_recovery_result_without_vendor_types() {
    let provider = MemoryProvider::default();
    let mut client = Client::open(ClientConfig {
        network: Network::Direct,
        secret: Some(([11; 32]).into()),
        transport: Default::default(),
        storage: Some((StorageConfig::memory(&provider)).into()),
    })
    .unwrap();
    client.create_workspace("Owner", None).unwrap();

    let pending: Option<ReceivedProtectedPublication> = client.poll_pending_object().unwrap();
    assert!(pending.is_none());
    client.close().unwrap();
}

#[test]
fn typed_client_exposes_recovery_request_lifecycle() {
    let provider = MemoryProvider::default();
    let mut client = Client::open(ClientConfig {
        network: Network::Direct,
        secret: Some(([15; 32]).into()),
        transport: Default::default(),
        storage: Some((StorageConfig::memory(&provider)).into()),
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
    let owner_provider = MemoryProvider::default();
    let reader_provider = MemoryProvider::default();
    let mut owner = Client::open(ClientConfig {
        network: Network::Direct,
        secret: Some(([16; 32]).into()),
        transport: Default::default(),
        storage: Some((StorageConfig::memory(&owner_provider)).into()),
    })
    .unwrap();
    let mut reader = Client::open(ClientConfig {
        network: Network::Direct,
        secret: Some(([17; 32]).into()),
        transport: Default::default(),
        storage: Some((StorageConfig::memory(&reader_provider)).into()),
    })
    .unwrap();
    let workspace = owner
        .create_workspace("Owner", Some("Recovery proof".into()))
        .unwrap();
    let candidate = owner.stage_invitation(0).unwrap();
    let invitation = owner.adopt_invitation(&candidate).unwrap();
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
    let joined_owner = owner.adopt_admission(&staged).unwrap();
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
    let joined_reader = reader.adopt_join(&staged).unwrap();
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
    owner.adopt_protected_publication(&staged).unwrap();

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
    assert_eq!(staged.publication_count(), 1);
    let adoption = reader.adopt_recovery(&staged).unwrap();
    assert_eq!(adoption.recovered_publications, 1);

    // Recovered objects wait in the durable inbox until acknowledged.
    let recovered = reader.poll_pending_object().unwrap().unwrap();
    assert_eq!(recovered.workspace, workspace.workspace);
    assert_eq!(recovered.topic, "streams/example");
    assert_eq!(recovered.payload, payload);
    assert_eq!(reader.poll_pending_object().unwrap(), Some(recovered.clone()));
    let acknowledged = reader.stage_object_acknowledgement(&recovered).unwrap();
    reader
        .adopt_protected_reception(&acknowledged)
        .unwrap();
    assert_eq!(reader.poll_pending_object().unwrap(), None);

    reader.close().unwrap();
    owner.close().unwrap();
}

#[test]
fn typed_client_rejects_wrong_publication_workspace_before_staging() {
    let provider = MemoryProvider::default();
    let mut client = Client::open(ClientConfig {
        network: Network::Direct,
        secret: Some(([18; 32]).into()),
        transport: Default::default(),
        storage: Some((StorageConfig::memory(&provider)).into()),
    })
    .unwrap();
    let workspace = client.create_workspace("Owner", None).unwrap();
    let revision = workspace.epoch + 1;
    client.install_workspace_policy(revision).unwrap();

    let mut other = workspace.workspace;
    other[0] ^= 1;
    let rejected = client
        .stage_protected_publication(other, revision, "streams/example", [1; 16], vec![1])
        .unwrap_err();
    assert_eq!(rejected.code(), ErrorCode::InvalidInput, "{rejected}");

    // Nothing was staged: the session still accepts ordinary operations.
    client.member_roster().unwrap();
    let staged = client
        .stage_protected_publication(
            workspace.workspace,
            revision,
            "streams/example",
            [2; 16],
            vec![2],
        )
        .unwrap();
    assert_eq!(staged.workspace(), workspace.workspace);
    client.adopt_protected_publication(&staged).unwrap();
    client.close().unwrap();
}

#[test]
fn typed_client_restores_only_with_matching_freshness_anchor() {
    let directory = tempfile::tempdir().unwrap();
    let root = [19; 32];
    let mut client = Client::open(ClientConfig {
        network: Network::Direct,
        secret: Some((root).into()),
        transport: Default::default(),
        storage: Some((StorageConfig::sqlite(directory.path(), root)).into()),
    })
    .unwrap();
    let workspace = client.create_workspace("Owner", None).unwrap();
    let anchor = client.record_freshness().unwrap();
    client.close().unwrap();

    let mut stale = anchor;
    stale.revision += 1;
    let mut client = Client::open(ClientConfig {
        network: Network::Direct,
        secret: Some((root).into()),
        transport: Default::default(),
        storage: Some((StorageConfig::sqlite(directory.path(), root)).into()),
    })
    .unwrap();
    let rejected = client
        .restore_workspace(workspace.workspace, Some(stale))
        .unwrap_err();
    assert_eq!(rejected.code(), ErrorCode::StorageFailed);
    client
        .restore_workspace(workspace.workspace, Some(anchor))
        .unwrap();
    assert_eq!(client.record_freshness().unwrap(), anchor);
    client.close().unwrap();
}

#[test]
fn typed_client_exposes_workspace_roster_and_profile_projection() {
    let provider = MemoryProvider::default();
    let mut client = Client::open(ClientConfig {
        network: Network::Direct,
        secret: Some(([12; 32]).into()),
        transport: Default::default(),
        storage: Some((StorageConfig::memory(&provider)).into()),
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
    let provider = MemoryProvider::default();
    let mut client = Client::open(ClientConfig {
        network: Network::Direct,
        secret: Some(([13; 32]).into()),
        transport: Default::default(),
        storage: Some((StorageConfig::memory(&provider)).into()),
    })
    .unwrap();
    let workspace = client
        .create_workspace("Owner", Some("Field Team".into()))
        .unwrap();

    let candidate = client.stage_invitation(0).unwrap();
    let invitation = client.adopt_invitation(&candidate).unwrap();
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
    // +1: registering the invitation now costs an epoch.
    assert_eq!(inspected.epoch, 1);
    client.close().unwrap();
}

#[test]
fn typed_client_reports_connectivity_without_exposing_transport_types() {
    let provider = MemoryProvider::default();
    let mut client = Client::open(ClientConfig {
        network: Network::Direct,
        secret: Some(([14; 32]).into()),
        transport: Default::default(),
        storage: Some((StorageConfig::memory(&provider)).into()),
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
#[cfg(feature = "test-fixtures")]
fn typed_client_routes_opaque_publication_and_reports_interest() {
    let mut publisher = Client::open(ClientConfig {
        network: Network::Direct,
        secret: Some(([8; 32]).into()),
        transport: Default::default(),
        storage: None,
    })
    .unwrap();
    let mut subscriber = Client::open(ClientConfig {
        network: Network::Direct,
        secret: Some(([9; 32]).into()),
        transport: Default::default(),
        storage: None,
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

/// The admission ops run typed (no JSON) and report typed error codes made
/// where the failure happens (ADR A1 step 2).
#[test]
fn typed_admission_ops_report_codes_and_pages() {
    use arachne_runtime::ErrorCode;
    let provider = MemoryProvider::default();
    let mut owner = Client::open(ClientConfig {
        network: Network::Direct,
        secret: Some(([21; 32]).into()),
        transport: Default::default(),
        storage: Some((StorageConfig::memory(&provider)).into()),
    })
    .unwrap();
    owner.create_workspace("Owner", None).unwrap();
    let page = owner.admission_approvals(None, None).unwrap();
    assert!(page.approvals.is_empty());
    assert!(page.complete);
    assert_eq!(page.next_after, None);
    let error = owner.admission_approvals(None, Some(65)).unwrap_err();
    assert_eq!(error.code(), ErrorCode::InvalidInput);
    assert_eq!(error.code(), ErrorCode::InvalidInput);
    assert_eq!(
        owner.acknowledge_admission_approval([1; 32]).unwrap_err().code(),
        ErrorCode::WrongState
    );
    assert_eq!(
        owner.send_admission_reply().unwrap_err().code(),
        ErrorCode::WrongState
    );
    // A candidate is an opaque object: the wrong adopt method does not
    // compile, and a used candidate is stale.
    let staged = owner.stage_invitation(0).unwrap();
    let invitation = owner.adopt_invitation(&staged).unwrap();
    assert!(!invitation.invitation.is_empty());
    let error = owner.adopt_invitation(&staged).unwrap_err();
    assert_eq!(error.code(), ErrorCode::CandidateStale, "{error}");
    assert!(!owner.poll_control().unwrap());
    owner.close().unwrap();
}

/// Management, invitation and workspace-name ops, typed end to end.
#[test]
fn typed_management_invitation_and_name_ops() {
    use arachne_runtime::{ErrorCode, InvitationKind, MemberAction};
    let provider = MemoryProvider::default();
    let mut owner = Client::open(ClientConfig {
        network: Network::Direct,
        secret: Some(([22; 32]).into()),
        transport: Default::default(),
        storage: Some((StorageConfig::memory(&provider)).into()),
    })
    .unwrap();
    let workspace = owner.create_workspace("Owner", Some("Team".into())).unwrap();

    let renamed = owner.stage_workspace_name("Field Team").unwrap();
    assert_eq!(renamed.workspace(), workspace.workspace);
    let adopted = owner.adopt_admission(&renamed).unwrap();
    assert_eq!(adopted.workspace_name.as_deref(), Some("Field Team"));

    let personal = owner
        .stage_invitation_of(0, InvitationKind::Personal)
        .unwrap();
    let link = owner.adopt_invitation(&personal).unwrap();
    let controls = owner.invitation_controls().unwrap();
    assert_eq!(controls.len(), 1);
    assert!(controls[0].personal);
    assert_eq!(controls[0].key, link.invitation_key);
    let details = owner
        .inspect_invitation(&link.invitation, &link.checkpoint)
        .unwrap();
    assert!(details.personal);

    let disabled = owner
        .stage_management(MemberAction::DisableInvitation(link.invitation_key))
        .unwrap();
    owner.adopt_admission(&disabled).unwrap();
    assert!(!owner.invitation_controls().unwrap()[0].enabled);

    // A management action on a stranger is refused with a code.
    let error = owner.stage_management(MemberAction::Promote([9; 32])).unwrap_err();
    assert_ne!(error.code(), ErrorCode::Internal, "{error}");

    // The last member leaves alone; adopting the removal ends the session.
    let leave = owner.stage_solo_leave().unwrap();
    let removed = owner.adopt_removal(&leave).unwrap();
    assert_eq!(removed.workspace, workspace.workspace);
    assert_eq!(owner.member_roster().unwrap_err().code(), ErrorCode::Closed);
    let _ = owner.close();
}
