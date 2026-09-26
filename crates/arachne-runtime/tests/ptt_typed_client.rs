use arachne_runtime::{
    Client, ClientConfig, ErrorCode, JoinAdmissionStep, MemoryProvider, Network,
    ReceivedProtectedPublication, StorageConfig,
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
    let owner_store = common::directory();
    let reader_store = common::directory();
    let owner_config = ClientConfig {
        network: Network::Direct,
        secret: Some((owner_secret).into()),
        transport: Default::default(),
        storage: Some((StorageConfig::sqlite(owner_store.path(), owner_root)).into()),
    };
    let reader_config = ClientConfig {
        network: Network::Direct,
        secret: Some((reader_secret).into()),
        transport: Default::default(),
        storage: Some((StorageConfig::sqlite(reader_store.path(), reader_root)).into()),
    };
    let owner = Client::open(owner_config.clone()).unwrap();
    let mut reader = Client::open(reader_config.clone()).unwrap();

    let workspace = owner
        .create_workspace("Owner", Some("Object inbox proof".into()))
        .unwrap();
    let invitation = owner.stage_invitation(0).unwrap();
    let invitation = owner.adopt_invitation(&invitation).unwrap();
    reader
        .add_address_hint(
            invitation.peer,
            &invitation.address.replace("0.0.0.0:", "127.0.0.1:"),
        )
        .unwrap();
    let join = reader
        .begin_join(&invitation.invitation, &invitation.checkpoint, "Reader")
        .unwrap();
    let candidate = owner
        .stage_admission(join.endpoint, &join.admission_request)
        .unwrap();
    let joined_owner = owner.adopt_admission(&candidate).unwrap();
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
    let joined_reader = reader.adopt_join(&candidate).unwrap();
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

    // Protected objects also use the normal Iroh data path before MoQ is enabled.
    let ordinary_payload = b"ordinary protected publication".to_vec();
    let candidate = owner
        .stage_protected_publication(
            workspace.workspace,
            revision,
            topic,
            ([1; 16]).into(),
            ordinary_payload.clone(),
        )
        .unwrap();
    let delivered = owner.adopt_protected_publication(&candidate).unwrap();
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
    reader.adopt_protected_reception(&candidate).unwrap();
    let ordinary = reader.poll_pending_object().unwrap().unwrap();
    assert_eq!(ordinary.payload, ordinary_payload);
    let ack = reader.stage_object_acknowledgement(&ordinary).unwrap();
    reader.adopt_protected_reception(&ack).unwrap();

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
            ([2; 16]).into(),
            payload.clone(),
        )
        .unwrap();
    let delivered = owner.adopt_protected_publication(&candidate).unwrap();
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
    reader.adopt_protected_reception(&candidate).unwrap();
    let pending = reader.poll_pending_object().unwrap().unwrap();
    assert_eq!(pending.workspace, workspace.workspace);
    assert_eq!(pending.revision, revision);
    assert_eq!(pending.endpoint, owner.endpoint().unwrap().endpoint_key);
    assert_eq!(pending.topic, topic);
    assert_eq!(pending.id, ([2; 16]).into());
    assert_eq!(pending.payload, payload);
    assert_eq!(pending.sequence, Some(2));

    let recording = reader_store.path().join("recording.bin");
    let mut file = fs::File::create(&recording).unwrap();
    file.write_all(&pending.payload).unwrap();
    file.sync_all().unwrap();
    drop(file);

    let reader_anchor = reader.record_freshness().unwrap();
    reader.close().unwrap();
    reader = Client::open(reader_config.clone()).unwrap();
    reader
        .restore_workspace(workspace.workspace, Some(reader_anchor))
        .unwrap();
    let restored: ReceivedProtectedPublication = reader.poll_pending_object().unwrap().unwrap();
    assert_eq!(restored, pending);
    assert_eq!(fs::read(&recording).unwrap(), payload);

    let candidate = reader.stage_object_acknowledgement(&restored).unwrap();
    reader.adopt_protected_reception(&candidate).unwrap();
    let reader_anchor = reader.record_freshness().unwrap();
    reader.close().unwrap();
    reader = Client::open(reader_config).unwrap();
    reader
        .restore_workspace(workspace.workspace, Some(reader_anchor))
        .unwrap();
    assert!(reader.poll_pending_object().unwrap().is_none());

    reader.close().unwrap();
    owner.close().unwrap();
}

#[test]
fn typed_inbox_requires_native_storage_and_survives_restart() {
    let ephemeral = Client::open(ClientConfig {
        network: Network::Direct,
        secret: Some(([33; 32]).into()),
        transport: Default::default(),
        storage: None,
    })
    .unwrap();
    assert_eq!(
        ephemeral
            .create_workspace("Ephemeral", None)
            .unwrap_err()
            .code(),
        ErrorCode::WrongState
    );
    ephemeral.close().unwrap();

    let store = common::directory();
    let config = ClientConfig {
        network: Network::Direct,
        secret: Some(([34; 32]).into()),
        transport: Default::default(),
        storage: Some((StorageConfig::sqlite(store.path(), [134; 32])).into()),
    };
    let durable = Client::open(config.clone()).unwrap();
    let workspace = durable.create_workspace("Durable", None).unwrap();
    let anchor = durable.record_freshness().unwrap();
    durable.close().unwrap();

    let durable = Client::open(config).unwrap();
    durable
        .restore_workspace(workspace.workspace, Some(anchor))
        .unwrap();
    assert!(durable.poll_pending_object().unwrap().is_none());
    durable.close().unwrap();
}

#[test]
fn failed_object_save_prevents_adoption_and_further_publication() {
    let provider = MemoryProvider::default();
    let client = Client::open(ClientConfig {
        network: Network::Direct,
        secret: Some(([35; 32]).into()),
        transport: Default::default(),
        storage: Some((StorageConfig::memory(&provider)).into()),
    })
    .unwrap();
    let workspace = client.create_workspace("Owner", None).unwrap();
    let candidate = client
        .stage_protected_publication(
            workspace.workspace,
            1,
            "streams/example",
            ([2; 16]).into(),
            vec![1],
        )
        .unwrap();
    provider.fail_next_commit();
    assert_eq!(
        client
            .adopt_protected_publication(&candidate)
            .unwrap_err()
            .code(),
        ErrorCode::StorageFailed
    );
    assert!(client.adopt_protected_publication(&candidate).is_err());
    assert!(
        client
            .stage_protected_publication(
                workspace.workspace,
                1,
                "streams/example",
                ([3; 16]).into(),
                vec![1]
            )
            .is_err()
    );
    client.close().unwrap();
}
