//! End-to-end checks through the same types that foreign bindings export.
use arachne_runtime::*;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn open(seed: u8, provider: &MemoryProvider) -> Arc<Client> {
    Client::open(ClientConfig {
        network: Network::Direct,
        secret: Some([seed; 32].into()),
        transport: TransportOptions {
            deadline: Some(Duration::from_secs(3)),
            ..Default::default()
        },
        storage: Some(StorageConfig::memory(provider).into()),
    })
    .unwrap()
}

fn connect(from: &Client, to: &Client) {
    let endpoint = to.endpoint().unwrap();
    let address: std::net::SocketAddr = endpoint.bound_address.parse().unwrap();
    from.add_address_hint(
        endpoint.endpoint_key,
        &format!("127.0.0.1:{}", address.port()),
    )
    .unwrap();
}

fn serve_until<T: Send>(server: &Arc<Client>, request: impl FnOnce() -> T + Send) -> T {
    std::thread::scope(|scope| {
        let task = scope.spawn(request);
        let stop = Instant::now() + Duration::from_secs(10);
        while !task.is_finished() {
            server.drive_workspace().unwrap();
            assert!(Instant::now() < stop, "peer operation did not finish");
            std::thread::sleep(Duration::from_millis(2));
        }
        task.join().unwrap()
    })
}

fn join(owner: &Arc<Client>, reader: &Arc<Client>, invitation: &InvitationInfo, name: &str) {
    connect(reader, owner);
    connect(owner, reader);
    let begin = reader
        .begin_join(&invitation.invitation, &invitation.checkpoint, name)
        .unwrap();
    let candidate = owner
        .stage_admission(begin.endpoint, &begin.admission_request)
        .unwrap();
    owner.adopt_admission(&candidate).unwrap();
    let grant = match serve_until(owner, || reader.request_admission(invitation.peer).unwrap()) {
        AdmissionResponse::Granted { grant } => grant,
        value => panic!("expected retained admission grant: {value:?}"),
    };
    assert_eq!(
        owner.stage_join_grant(&grant).unwrap_err().code(),
        ErrorCode::WrongState
    );
    let candidate = reader.stage_join_grant(&grant).unwrap();
    let adopted = reader.adopt_join(&candidate).unwrap();
    assert!(adopted.durable);
    assert_eq!(
        reader.adopt_join(&candidate).unwrap_err().code(),
        ErrorCode::CandidateStale
    );
    assert_eq!(
        owner.member_roster().unwrap().members.len(),
        reader.member_roster().unwrap().members.len()
    );
}

fn catch_up(owner: &Arc<Client>, reader: &Arc<Client>) {
    let peer = owner.endpoint().unwrap().endpoint_key;
    let stop = Instant::now() + Duration::from_secs(10);
    loop {
        if reader.member_roster().unwrap().epoch == owner.member_roster().unwrap().epoch {
            return;
        }
        reader.fetch_membership_update(peer, false).unwrap();
        let update = loop {
            owner.drive_workspace().unwrap();
            if let Some(update) = reader.poll_membership_update().unwrap() {
                break update;
            }
            assert!(Instant::now() < stop, "membership update did not arrive");
            std::thread::sleep(Duration::from_millis(2));
        };
        assert_eq!(
            owner.stage_membership_update(&update).unwrap_err().code(),
            ErrorCode::WrongState
        );
        match reader.stage_membership_update(&update).unwrap() {
            MembershipCandidate::Workspace { candidate } => {
                reader.adopt_admission(&candidate).unwrap();
            }
            other => panic!("unexpected membership candidate: {other:?}"),
        }
        assert!(Instant::now() < stop, "membership did not converge");
    }
}

fn current(
    server: &Arc<Client>,
    reader: &Arc<Client>,
    request: CurrentViewRequest,
) -> CurrentViewAdoption {
    let status = reader.fetch_current_view(request).unwrap();
    assert!(matches!(status, CurrentViewStatus::Pending { .. }));
    let stop = Instant::now() + Duration::from_secs(10);
    loop {
        server.poll_control().unwrap();
        if let Some(status) = reader.poll_current_view().unwrap() {
            assert!(
                matches!(status, CurrentViewStatus::Ready { .. }),
                "{status:?}"
            );
            break;
        }
        assert!(Instant::now() < stop, "current view did not arrive");
        std::thread::sleep(Duration::from_millis(2));
    }
    let candidate = reader.stage_current_view().unwrap();
    assert_eq!(
        server.adopt_current_view(&candidate).unwrap_err().code(),
        ErrorCode::WrongState
    );
    reader.adopt_current_view(&candidate).unwrap()
}

#[test]
fn typed_admission_membership_and_holder_recovery_keep_native_authority() {
    let owner = open(141, &MemoryProvider::default());
    let holder = open(142, &MemoryProvider::default());
    let reader_provider = MemoryProvider::default();
    let reader = open(143, &reader_provider);
    let workspace = owner
        .create_workspace("Owner", Some("Typed flow".into()))
        .unwrap();
    let invitation = owner
        .adopt_invitation(&owner.stage_invitation(0).unwrap())
        .unwrap();
    join(&owner, &holder, &invitation, "Holder");
    join(&owner, &reader, &invitation, "Reader");
    catch_up(&owner, &holder);
    connect(&reader, &holder);
    connect(&holder, &reader);
    let revision = owner.member_roster().unwrap().epoch + 1;
    for client in [&owner, &holder, &reader] {
        client.install_workspace_policy(revision).unwrap();
    }
    let authority = owner
        .member_roster()
        .unwrap()
        .members
        .into_iter()
        .find(|member| member.endpoint == owner.endpoint().unwrap().endpoint_key)
        .unwrap()
        .id;
    let selector = [81; 32].into();
    let metadata = PublicationCurrent {
        selector,
        replacement_key: [82; 32].into(),
        expires_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600,
        tombstone: false,
    };
    let publication = owner
        .stage_protected_publication_with_current(
            workspace.workspace,
            revision,
            "objects/catalog",
            [7; 16].into(),
            vec![1, 2, 3],
            Some(metadata),
        )
        .unwrap();
    owner.adopt_protected_publication(&publication).unwrap();
    let held = current(
        &owner,
        &holder,
        CurrentViewRequest {
            peer: Some(owner.endpoint().unwrap().endpoint_key),
            authority,
            revision,
            topic: "objects/catalog".into(),
            selector,
        },
    );
    assert_eq!(held.pending, 1);
    let pending = holder.poll_pending_object().unwrap().unwrap();
    assert_eq!(pending.current, Some(metadata));
    holder
        .adopt_protected_reception(&holder.stage_object_acknowledgement(&pending).unwrap())
        .unwrap();
    owner.close().unwrap();
    let recovered = current(
        &holder,
        &reader,
        CurrentViewRequest {
            peer: Some(holder.endpoint().unwrap().endpoint_key),
            authority,
            revision,
            topic: "objects/catalog".into(),
            selector,
        },
    );
    assert_eq!(recovered.pending, 1);
    let anchor = reader.record_freshness().unwrap();
    reader.close().unwrap();
    let reader = open(143, &reader_provider);
    reader
        .restore_workspace(workspace.workspace, Some(anchor))
        .unwrap();
    let pending = reader.poll_pending_object().unwrap().unwrap();
    assert_eq!(pending.payload, [1, 2, 3]);
    assert_eq!(pending.current, Some(metadata));
    reader
        .adopt_protected_reception(&reader.stage_object_acknowledgement(&pending).unwrap())
        .unwrap();
    assert!(reader.poll_pending_object().unwrap().is_none());
    reader.close().unwrap();
    holder.close().unwrap();
}

fn resource_done(client: &Client, started: ResourceStatus) -> ClientResult<ResourceStatus> {
    let ResourceStatus::Started { id } = started else {
        panic!("resource did not start: {started:?}")
    };
    let stop = Instant::now() + Duration::from_secs(10);
    loop {
        let status = client.resource(ResourceRequest::Poll { id })?;
        if !matches!(status, ResourceStatus::Running { .. }) {
            return Ok(status);
        }
        assert!(Instant::now() < stop, "resource operation did not finish");
        std::thread::sleep(Duration::from_millis(2));
    }
}

#[test]
fn typed_resource_transfer_preserves_authorization_and_ticket() {
    let owner = open(145, &MemoryProvider::default());
    let reader = open(146, &MemoryProvider::default());
    let observer = open(147, &MemoryProvider::default());
    owner.create_workspace("Owner", None).unwrap();
    let invitation = owner
        .adopt_invitation(&owner.stage_invitation(0).unwrap())
        .unwrap();
    join(&owner, &reader, &invitation, "Reader");
    join(&owner, &observer, &invitation, "Observer");
    catch_up(&owner, &reader);
    let revision = owner.member_roster().unwrap().epoch + 1;
    for client in [&owner, &reader, &observer] {
        client.install_workspace_policy(revision).unwrap();
    }
    let owner_member = owner
        .member_roster()
        .unwrap()
        .members
        .into_iter()
        .find(|m| m.self_member)
        .unwrap()
        .id;
    let reader_member = reader
        .member_roster()
        .unwrap()
        .members
        .into_iter()
        .find(|m| m.self_member)
        .unwrap()
        .id;
    let source = tempfile::tempdir().unwrap();
    let destination = tempfile::tempdir().unwrap();
    let bytes = vec![17u8; 4097];
    std::fs::write(source.path().join("object.bin"), &bytes).unwrap();
    let prepared = resource_done(
        &owner,
        owner
            .resource(ResourceRequest::Prepare {
                member: reader_member,
                root: source.path().display().to_string(),
                path: source.path().join("object.bin").display().to_string(),
            })
            .unwrap(),
    )
    .unwrap();
    let ResourceStatus::Prepared { ticket } = prepared else {
        panic!("resource was not prepared: {prepared:?}")
    };
    assert_eq!(ticket.size, bytes.len() as u64);
    let result = resource_done(
        &reader,
        reader
            .resource(ResourceRequest::Fetch {
                member: owner_member,
                root: destination.path().display().to_string(),
                path: destination.path().join("copy.bin").display().to_string(),
                ticket: ticket.clone(),
            })
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        result,
        ResourceStatus::Complete {
            bytes: bytes.len() as u64
        }
    );
    assert_eq!(
        std::fs::read(destination.path().join("copy.bin")).unwrap(),
        bytes
    );
    let outsider_dir = tempfile::tempdir().unwrap();
    let refused = resource_done(
        &observer,
        observer
            .resource(ResourceRequest::Fetch {
                member: owner_member,
                root: outsider_dir.path().display().to_string(),
                path: outsider_dir
                    .path()
                    .join("forbidden.bin")
                    .display()
                    .to_string(),
                ticket: ticket.clone(),
            })
            .unwrap(),
    )
    .unwrap_err();
    assert_eq!(refused.code(), ErrorCode::TransportFailed);
    assert!(!outsider_dir.path().join("forbidden.bin").exists());
    assert!(
        reader
            .resource(ResourceRequest::Fetch {
                member: [251; 32].into(),
                root: destination.path().display().to_string(),
                path: destination
                    .path()
                    .join("forbidden.bin")
                    .display()
                    .to_string(),
                ticket,
            })
            .is_err()
    );
    let denied = owner
        .resource(ResourceRequest::Prepare {
            member: reader_member,
            root: source.path().display().to_string(),
            path: "../outside.bin".into(),
        })
        .unwrap();
    let refused = resource_done(&owner, denied).unwrap_err();
    assert_eq!(refused.code(), ErrorCode::TransportFailed);
    observer.close().unwrap();
    reader.close().unwrap();
    owner.close().unwrap();
}
