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

fn synthetic(index: usize) -> [u8; 32] {
    let mut value = [0; 32];
    value[..8].copy_from_slice(&(index as u64 + 1).to_be_bytes());
    value[8..16].copy_from_slice(&(!(index as u64)).to_be_bytes());
    value
}

/// An owner workspace for `endpoint` with at least `size` members.
fn grown(endpoint: [u8; 32], size: usize) -> Workspace {
    let owner = Workspace::create(endpoint, "Large owner").unwrap();
    let (registration, invitation, checkpoint) = owner.prepare_invitation(0, false, false).unwrap();
    let mut owner = registration.workspace;
    let mut next = 0;
    while owner.member_count() < size {
        let range = next..(next + MAX_ADMISSION_BATCH);
        let requests: Vec<_> = range
            .clone()
            .map(|index| {
                PendingJoin::from_invitation(&invitation, &checkpoint, synthetic(index), "Member")
                    .unwrap()
                    .admission_request()
                    .unwrap()
                    .to_vec()
            })
            .collect();
        let validated: Vec<_> = range
            .clone()
            .zip(&requests)
            .map(|(index, request)| match owner.assess_admission(synthetic(index), request).unwrap() {
                AdmissionAssessment::Ready(validated) => validated,
                _ => panic!("open invitation needs no approval"),
            })
            .collect();
        let entries: Vec<_> = range
            .clone()
            .zip(requests.iter().zip(&validated))
            .map(|(index, (request, validated))| (synthetic(index), request.as_slice(), validated))
            .collect();
        owner = owner.prepare_validated_admission_batch(&entries).unwrap().workspace;
        next = range.end;
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
    let address = info["bound_address"].as_str().unwrap().replace("0.0.0.0:", "127.0.0.1:");

    // Past 500 members, so the checkpoint spans more than one control reply.
    let workspace = grown(owner_peer, 520);
    let members = workspace.member_count();
    {
        let shared = session(owner).unwrap();
        let mut guard = shared.lock().unwrap();
        commit_workspace(guard.as_mut().unwrap(), workspace);
    }
    // A roster this size is past the legacy sealed-snapshot budget, so the
    // owner keeps records, saving each candidate before adopting it.
    let dirs: Vec<_> = (0..2).map(|_| tempfile::tempdir().unwrap()).collect();
    persistence::enable_record_storage(owner, &dirs[0].path().join("owner.db"), &[241; 32]).unwrap();
    let staged =
        call(owner, json!({"op":"stage_invitation","personal":false,"expires_at":0})).unwrap();
    let snapshot: Vec<u8> = serde_json::from_value(staged["snapshot"].clone()).unwrap();
    persistence::save_candidate(owner, &snapshot).unwrap();
    let adopted = call(owner, json!({"op":"adopt_admission","snapshot":staged["snapshot"]})).unwrap();
    let invitation = adopted["issued_invitation"].clone();
    let checkpoint: Vec<u8> = serde_json::from_value(invitation["checkpoint"].clone()).unwrap();
    // The regime under test: the old single 64 KiB checkpoint bound, and one
    // control reply, are both too small for this checkpoint.
    assert!(checkpoint.len() > CHECKPOINT_PAGE_BYTES, "checkpoint is only {} bytes", checkpoint.len());
    eprintln!("B3a runtime: {members} members, checkpoint {} bytes", checkpoint.len());

    let joiner = create(Some(&[242; 32])).unwrap();
    let _joiner = Closing(joiner);
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
    persistence::enable_record_storage(joiner, &dirs[1].path().join("joiner.db"), &[242; 32])
        .unwrap();
    call(joiner, json!({"op":"add_address_hint","peer":owner_peer,"address":address})).unwrap();

    // The owner is driven on its own thread, so a joiner failure surfaces
    // here instead of leaving the owner waiting for work forever.
    let driver = std::thread::spawn(move || {
        if !wait_for_work(owner).unwrap_or(false) {
            return;
        }
        loop {
            let Ok(value) = call(owner, json!({"op":"drive_workspace"})) else { return };
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
