use arachne_runtime::{
    Client, ClientConfig, ErrorKind, JoinAdmissionStep, MemberKind, Network, PeerPolicy, Presence,
    ReceivedProtectedPublication, RecoveryRangeRequest, RecoveryRangeStatus, WorkspacePhase,
};
use std::{
    fs,
    io::Write,
    time::{Duration, Instant},
};
mod common;
#[test]
fn typed_clients_persist_authenticated_inbox_objects_before_acknowledging() {
    let owner_secret = [31; 32];
    let reader_secret = [32; 32];
    let owner_root = [131; 32];
    let reader_root = [132; 32];
    let owner_config = ClientConfig {
        network: Network::Direct,
        secret: Some(owner_secret),
        transport: Default::default(),
    };
    let reader_config = ClientConfig {
        network: Network::Direct,
        secret: Some(reader_secret),
        transport: Default::default(),
    };
    let mut owner = Client::open(owner_config.clone()).unwrap();
    let mut reader = Client::open(reader_config.clone()).unwrap();
    let owner_store = common::directory();
    let reader_store = common::directory();
    let owner_database = owner_store.path().join("workspace.db");
    let reader_database = reader_store.path().join("workspace.db");

    let workspace = owner
        .create_workspace("Owner", Some("Object inbox proof"))
        .unwrap();
    owner
        .enable_record_storage(&owner_database, &owner_root)
        .unwrap();
    let invitation = owner.stage_invitation(0).unwrap();
    owner.save_candidate(&invitation.snapshot).unwrap();
    let invitation = owner.adopt_invitation(&invitation.snapshot).unwrap();
    reader
        .add_address_hint(
            invitation.peer,
            &invitation.address.replace("0.0.0.0:", "127.0.0.1:"),
        )
        .unwrap();
    let join = reader
        .begin_join(&invitation.invitation, &invitation.checkpoint, "Reader")
        .unwrap();
    reader
        .enable_record_storage(&reader_database, &reader_root)
        .unwrap();
    let candidate = owner
        .stage_admission(join.endpoint, &join.admission_request)
        .unwrap();
    owner.save_candidate(&candidate.snapshot).unwrap();
    let joined_owner = owner.adopt_admission(&candidate.snapshot).unwrap();
    let reply = owner
        .retained_admission(join.endpoint, &join.admission_request)
        .unwrap();
    let candidate = reader
        .stage_join(
            &reply.welcome,
            &[JoinAdmissionStep {
                commit: reply.commit,
                authorization: reply.authorization,
            }],
        )
        .unwrap();
    reader.save_candidate(&candidate.snapshot).unwrap();
    let joined_reader = reader.adopt_join(&candidate.snapshot).unwrap();
    assert_eq!(joined_owner.epoch, joined_reader.epoch);

    let reader_endpoint = reader.endpoint().unwrap();
    owner
        .add_address_hint(
            reader_endpoint.endpoint_key,
            &reader_endpoint
                .bound_address
                .replace("0.0.0.0:", "127.0.0.1:"),
        )
        .unwrap();
    let revision = joined_owner.epoch + 1;
    let topic = "streams/ptt";
    owner.install_workspace_policy(revision).unwrap();
    reader.install_workspace_policy(revision).unwrap();
    reader
        .set_interest(workspace.workspace, revision, topic, true)
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        owner.poll_control().unwrap();
        if let Some(interest) = reader.poll_interest().unwrap() {
            assert!(interest.admission.failed.is_empty(), "{interest:?}");
            break;
        }
        assert!(
            Instant::now() < deadline,
            "object topic interest did not settle"
        );
        std::thread::sleep(Duration::from_millis(5));
    }

    // The legacy MLS publication path remains available before inbox cutover.
    let ordinary_payload = b"ordinary protected publication".to_vec();
    let candidate = owner
        .stage_protected_publication(
            workspace.workspace,
            revision,
            topic,
            [1; 16],
            ordinary_payload.clone(),
        )
        .unwrap();
    owner.save_candidate(&candidate.snapshot).unwrap();
    let delivered = owner
        .adopt_protected_publication(&candidate.snapshot)
        .unwrap();
    assert!(
        delivered.failed.is_empty(),
        "ordinary protected delivery: {delivered:?}"
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    let candidate = loop {
        owner.poll_control().unwrap();
        if let Some(candidate) = reader.poll_protected().unwrap() {
            break candidate;
        }
        assert!(
            Instant::now() < deadline,
            "ordinary protected publication did not arrive"
        );
        std::thread::sleep(Duration::from_millis(5));
    };
    reader.save_candidate(&candidate.snapshot).unwrap();
    reader
        .adopt_protected_reception(&candidate.snapshot)
        .unwrap();
    let ordinary = reader.poll_pending_object().unwrap().unwrap();
    assert_eq!(ordinary.payload, ordinary_payload);
    let ack = reader.stage_object_acknowledgement(&ordinary).unwrap();
    reader.save_candidate(&ack.snapshot).unwrap();
    reader.adopt_protected_reception(&ack.snapshot).unwrap();

    #[cfg(feature = "moq")]
    {
        owner
            .set_interest(workspace.workspace, revision, topic, true)
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            reader.poll_control().unwrap();
            if let Some(interest) = owner.poll_interest().unwrap() {
                assert!(interest.admission.failed.is_empty(), "{interest:?}");
                break;
            }
            assert!(
                Instant::now() < deadline,
                "owner topic interest did not settle"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        let owner_endpoint = owner.endpoint().unwrap().endpoint_key;
        let reader_endpoint = reader.endpoint().unwrap().endpoint_key;
        if owner_endpoint < reader_endpoint {
            reader
                .enable_moq_delivery(workspace.workspace, revision, owner_endpoint, topic)
                .unwrap();
            owner
                .enable_moq_delivery(workspace.workspace, revision, reader_endpoint, topic)
                .unwrap();
        } else {
            owner
                .enable_moq_delivery(workspace.workspace, revision, reader_endpoint, topic)
                .unwrap();
            reader
                .enable_moq_delivery(workspace.workspace, revision, owner_endpoint, topic)
                .unwrap();
        }
    }

    let payload = b"authenticated object recording".to_vec();
    let candidate = owner
        .stage_protected_publication(
            workspace.workspace,
            revision,
            topic,
            [2; 16],
            payload.clone(),
        )
        .unwrap();
    owner.save_candidate(&candidate.snapshot).unwrap();
    let delivered = owner
        .adopt_protected_publication(&candidate.snapshot)
        .unwrap();
    assert!(
        delivered.failed.is_empty(),
        "object protected delivery: {delivered:?}"
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    let candidate = loop {
        owner.poll_control().unwrap();
        if let Some(candidate) = reader.poll_protected().unwrap() {
            break candidate;
        }
        assert!(
            Instant::now() < deadline,
            "protected inbox object did not arrive"
        );
        std::thread::sleep(Duration::from_millis(5));
    };
    reader.save_candidate(&candidate.snapshot).unwrap();
    reader
        .adopt_protected_reception(&candidate.snapshot)
        .unwrap();
    let pending = reader.poll_pending_object().unwrap().unwrap();
    assert_eq!(pending.workspace, workspace.workspace);
    assert_eq!(pending.revision, revision);
    assert_eq!(pending.endpoint, owner.endpoint().unwrap().endpoint_key);
    assert_eq!(pending.topic, topic);
    assert_eq!(pending.id, [2; 16]);
    assert_eq!(pending.payload, payload);
    assert_eq!(pending.sequence, Some(2));

    let recording = reader_store.path().join("recording.bin");
    let mut file = fs::File::create(&recording).unwrap();
    file.write_all(&pending.payload).unwrap();
    file.sync_all().unwrap();
    drop(file);

    reader.close().unwrap();
    reader = Client::open(reader_config.clone()).unwrap();
    reader
        .restore_record_storage(&reader_database, &reader_root, workspace.workspace)
        .unwrap();
    let restored: ReceivedProtectedPublication = reader.poll_pending_object().unwrap().unwrap();
    assert_eq!(restored, pending);
    assert_eq!(fs::read(&recording).unwrap(), payload);

    let candidate = reader.stage_object_acknowledgement(&restored).unwrap();
    reader.save_candidate(&candidate.snapshot).unwrap();
    reader
        .adopt_protected_reception(&candidate.snapshot)
        .unwrap();
    reader.close().unwrap();
    reader = Client::open(reader_config).unwrap();
    reader
        .restore_record_storage(&reader_database, &reader_root, workspace.workspace)
        .unwrap();
    assert!(reader.poll_pending_object().unwrap().is_none());

    reader.close().unwrap();
    owner.close().unwrap();
}

#[test]
fn typed_inbox_is_available_for_durable_and_ephemeral_clients() {
    let mut ephemeral = Client::open(ClientConfig {
        network: Network::Direct,
        secret: Some([33; 32]),
        transport: Default::default(),
    })
    .unwrap();
    ephemeral.create_workspace("Ephemeral", None).unwrap();
    assert!(ephemeral.poll_pending_object().unwrap().is_none());
    ephemeral.close().unwrap();

    let secret = [34; 32];
    let root = [134; 32];
    let mut durable = Client::open(ClientConfig {
        network: Network::Direct,
        secret: Some(secret),
        transport: Default::default(),
    })
    .unwrap();
    let workspace = durable.create_workspace("Durable", None).unwrap();
    let store = common::directory();
    let database = store.path().join("workspace.db");
    durable.enable_record_storage(&database, &root).unwrap();
    durable.close().unwrap();

    let mut durable = Client::open(ClientConfig {
        network: Network::Direct,
        secret: Some(secret),
        transport: Default::default(),
    })
    .unwrap();
    durable
        .restore_record_storage(&database, &root, workspace.workspace)
        .unwrap();
    assert!(durable.poll_pending_object().unwrap().is_none());
    durable.close().unwrap();
}

#[test]
fn failed_object_save_prevents_adoption_and_further_publication() {
    let secret = [35; 32];
    let root = [135; 32];
    let mut client = Client::open(ClientConfig {
        network: Network::Direct,
        secret: Some(secret),
        transport: Default::default(),
    })
    .unwrap();
    let workspace = client.create_workspace("Owner", None).unwrap();
    let store = common::directory();
    client
        .enable_record_storage(&store.path().join("workspace.db"), &root)
        .unwrap();
    let candidate = client
        .stage_protected_publication(workspace.workspace, 1, "streams/example", [2; 16], vec![1])
        .unwrap();
    let mut invalid = candidate.snapshot.clone();
    *invalid.last_mut().unwrap() ^= 1;
    assert_eq!(
        client.save_candidate(&invalid).unwrap_err().kind(),
        ErrorKind::Storage
    );
    assert!(
        client
            .adopt_protected_publication(&candidate.snapshot)
            .is_err()
    );
    assert!(
        client
            .stage_protected_publication(
                workspace.workspace,
                1,
                "streams/example",
                [3; 16],
                vec![1]
            )
            .is_err()
    );
    client.close().unwrap();
}
