//! B3a end to end over the real runtime join path: an invitation issued by an
//! owner past 300 members is redeemed by a joiner that holds only the bearer
//! link and a peer. The joiner fetches the (paged) checkpoint over
//! authenticated Iroh, persists its pending join, sends a `DFJA\x03` request
//! that carries no checkpoint, verifies the history and adopts the Welcome.
//!
//! The owner's roster is built with the security crate's batch admission and
//! committed into the session directly: 300 separate runtime joiners would
//! test admission throughput, not the invitation checkpoint.
use super::*;
use arachne_security::{AdmissionAssessment, MAX_ADMISSION_BATCH, PendingJoin, Workspace};

fn call(handle: i64, request: Value) -> Result<Value, String> {
    serde_json::from_slice(&execute(handle, &serde_json::to_vec(&request).unwrap())?)
        .map_err(|error| error.to_string())
}

/// An owner workspace for `endpoint` with at least `size` members, each with
/// its own endpoint key.
fn grown(endpoint: &dyn arachne_security::EndpointSigner, size: usize) -> Workspace {
    use arachne_security::{EndpointKey, EndpointSigner};
    let owner = Workspace::create(endpoint, "Large owner").unwrap();
    let (registration, invitation, checkpoint) = owner.prepare_invitation(0, false, false).unwrap();
    let mut owner = registration.workspace;
    while owner.member_count() < size {
        let keys: Vec<_> = (0..MAX_ADMISSION_BATCH)
            .map(|_| EndpointKey::generate().unwrap())
            .collect();
        let requests: Vec<_> = keys
            .iter()
            .map(|key| {
                PendingJoin::from_invitation(&invitation, &checkpoint, key, "Member")
                    .unwrap()
                    .admission_request()
                    .unwrap()
                    .to_vec()
            })
            .collect();
        let validated: Vec<_> = keys
            .iter()
            .zip(&requests)
            .map(
                |(key, request)| match owner.assess_admission(key.endpoint(), request).unwrap() {
                    AdmissionAssessment::Ready(validated) => validated,
                    _ => panic!("open invitation needs no approval"),
                },
            )
            .collect();
        let entries: Vec<_> = keys
            .iter()
            .zip(requests.iter().zip(&validated))
            .map(|(key, (request, validated))| (key.endpoint(), request.as_slice(), validated))
            .collect();
        owner = owner
            .prepare_validated_admission_batch(&entries)
            .unwrap()
            .workspace;
    }
    owner
}

fn complete_join(handle: i64) -> Value {
    loop {
        let value = call(handle, json!({"op":"drive_join"})).unwrap();
        match value["state"].as_str() {
            Some("workspace_joined") => return value,
            Some("admission_pending") => assert!(wait_for_work(handle).unwrap()),
            Some("admission_waiting") => continue,
            state => panic!("unexpected join state: {state:?} {value}"),
        }
    }
}

/// Closes a session even when the test panics, so a failure here does not
/// exhaust the process-wide node limit for the tests that run after it.
struct Closing(i64);

impl Drop for Closing {
    fn drop(&mut self) {
        let _ = close(self.0);
    }
}

#[test]
fn a_joiner_redeems_an_invitation_past_three_hundred_members_over_the_runtime() {
    let owner = create(Some(&[241; 32])).unwrap();
    let _owner = Closing(owner);
    let info: Value = serde_json::from_str(&describe(owner).unwrap()).unwrap();
    let owner_peer: [u8; 32] = serde_json::from_value(info["endpoint_key"].clone()).unwrap();
    let address = info["bound_address"]
        .as_str()
        .unwrap()
        .replace("0.0.0.0:", "127.0.0.1:");

    // Past 500 members, so the checkpoint spans more than one control reply.
    let secret = iroh::SecretKey::from_bytes(&[241; 32]);
    assert_eq!(*secret.public().as_bytes(), owner_peer);
    let workspace = grown(&arachne_node::IrohEndpointSigner(&secret), 520);
    let members = workspace.member_count();
    // The owner keeps records: its roster is seeded into storage and restored.
    let dirs: Vec<_> = (0..2).map(|_| tempfile::tempdir().unwrap()).collect();
    let owner_storage = StorageConfig::sqlite(dirs[0].path(), [241; 32]);
    persistence::seed_workspace(
        &arachne_store::SqliteProvider::new(dirs[0].path(), [241; 32]),
        &workspace,
        None,
        None,
    )
    .unwrap();
    attach_storage(owner, owner_storage).unwrap();
    call(
        owner,
        json!({"op":"restore_workspace","workspace":workspace.id()}),
    )
    .unwrap();
    let staged = call(
        owner,
        json!({"op":"stage_invitation","personal":false,"expires_at":0}),
    )
    .unwrap();
    let adopted = call(
        owner,
        json!({"op":"adopt_admission","candidate":staged["candidate"]}),
    )
    .unwrap();
    let invitation = adopted["issued_invitation"].clone();
    let checkpoint: Vec<u8> = serde_json::from_value(invitation["checkpoint"].clone()).unwrap();
    // The regime under test: the old single 64 KiB checkpoint bound, and one
    // control reply, are both too small for this checkpoint.
    assert!(
        checkpoint.len() > crate::ops::join::CHECKPOINT_PAGE_BYTES,
        "checkpoint is only {} bytes",
        checkpoint.len()
    );
    eprintln!(
        "B3a runtime: {members} members, checkpoint {} bytes",
        checkpoint.len()
    );

    let joiner = create(Some(&[242; 32])).unwrap();
    let _joiner = Closing(joiner);
    attach_storage(joiner, StorageConfig::sqlite(dirs[1].path(), [242; 32])).unwrap();
    let pending = call(
        joiner,
        json!({
            "op":"begin_join",
            "display_name":"Late member",
            "invitation":invitation["invitation"].clone(),
            "peers":[owner_peer],
        }),
    )
    .unwrap();
    let workspace_id: [u8; 32] = serde_json::from_value(pending["workspace"].clone()).unwrap();
    call(
        joiner,
        json!({"op":"add_address_hint","peer":owner_peer,"address":address}),
    )
    .unwrap();

    // The owner is driven on its own thread, so a joiner failure surfaces
    // here instead of leaving the owner waiting for work forever.
    let driver = std::thread::spawn(move || {
        if !wait_for_work(owner).unwrap_or(false) {
            return;
        }
        loop {
            let Ok(value) = call(owner, json!({"op":"drive_workspace"})) else {
                return;
            };
            if value["state"] != "admission_queued" {
                assert_eq!(value["state"], "workspace_committed", "{value}");
                return;
            }
        }
    });
    let joined = complete_join(joiner);
    driver.join().unwrap();
    assert_eq!(joined["state"], "workspace_joined");
    assert_eq!(joined["workspace"], json!(workspace_id));
    let state = call(joiner, json!({"op":"workspace_state"})).unwrap();
    assert_eq!(state["workspace_ready"], true);
}
