//! A3g: every record the runtime saves fits the store's 1 MiB record limit
//! at the member counts the security bounds allow.
//!
//! Native storage saves a workspace as many records, not one sealed bundle:
//! the MLS provider values, retained admissions, join history and invitation
//! checkpoints (`security/*`), the object inbox with the publisher log
//! (`delivery/inbox`), and a pending join (`runtime/pending`). The inbox and
//! the pending join have fixed bounds. The MLS provider keeps the ratchet
//! tree as JSON, which grows with the roster past one record, so the runtime
//! saves long values as parts (all in one authenticated commit).
use arachne_security::{
    AdmissionAssessment, EndpointKey, EndpointSigner, MAX_ADMISSION_BATCH, MAX_CHECKPOINT,
    MAX_CHECKPOINT_TREE, MAX_JOIN_HISTORY_BYTES, MAX_SEALED_PENDING_JOIN,
    MAX_WORKSPACE_ATTACHMENT, PendingJoin, Workspace,
};
use arachne_store::MAX_RECORD_BYTES;
use serde_json::{Value, json};

mod common;

/// `owner` grown to `size` or more members, admitted in batches.
fn grown(owner: Workspace, size: usize) -> Workspace {
    let (registration, invitation, checkpoint) = owner.prepare_invitation(0, false, false).unwrap();
    let mut owner = registration.workspace;
    while owner.member_count() < size {
        let keys: Vec<_> = (0..MAX_ADMISSION_BATCH)
            .map(|_| EndpointKey::generate().unwrap())
            .collect();
        owner = owner
            .prepare_validated_admission_batch(&batch(&owner, &invitation, &checkpoint, &keys))
            .unwrap()
            .workspace;
    }
    owner
}

/// Admission entries for `keys` (owned requests and validations leak into
/// the returned borrow, so they are boxed and leaked: test-only sizes).
fn batch<'a>(
    owner: &Workspace,
    invitation: &arachne_security::Invitation,
    checkpoint: &[u8],
    keys: &[EndpointKey],
) -> Vec<([u8; 32], &'a [u8], &'a arachne_security::ValidatedAdmission)> {
    keys.iter()
        .map(|key| {
            let request: &'a [u8] = Box::leak(
                PendingJoin::from_invitation(invitation, checkpoint, key, "Member")
                    .unwrap()
                    .admission_request()
                    .unwrap()
                    .to_vec()
                    .into_boxed_slice(),
            );
            let validated = match owner.assess_admission(key.endpoint(), request).unwrap() {
                AdmissionAssessment::Ready(validated) => Box::leak(Box::new(validated)),
                _ => panic!("open invitation needs no approval"),
            };
            (key.endpoint(), request, &*validated)
        })
        .collect()
}

/// Members, the largest record (name, bytes) and the checkpoint tree bytes.
fn measure(owner: &Workspace) -> (usize, String, usize, usize) {
    let records = owner.export_records().unwrap();
    let (name, value) = records
        .iter()
        .max_by_key(|(_, value)| value.len())
        .unwrap();
    let (_, _, checkpoint) = owner.prepare_invitation(0, false, false).unwrap();
    let pin = u32::from_be_bytes(checkpoint[5..9].try_into().unwrap()) as usize;
    let tree = checkpoint.len() - 13 - pin;
    (
        owner.member_count(),
        String::from_utf8_lossy(name).chars().take(40).collect(),
        value.len(),
        tree,
    )
}

fn call(handle: i64, request: Value) -> Value {
    serde_json::from_slice(
        &arachne_runtime::execute(handle, &serde_json::to_vec(&request).unwrap()).unwrap(),
    )
    .unwrap()
}

/// A runtime session whose endpoint owns the workspace, the workspace grown
/// to `size`, seeded into SQLite storage, restored, then one name change
/// staged and adopted at that size. Returns the member count.
fn saves_stages_and_restores_at(size: usize) -> usize {
    let directory = common::directory();
    let root = [8; 32];
    let secret = [7; 32];
    let signer_key = iroh::SecretKey::from_bytes(&secret);
    let signer = arachne_node::IrohEndpointSigner(&signer_key);
    let owner = grown(Workspace::create(&signer, "Record bound owner").unwrap(), size);
    let (members, name, largest, tree) = measure(&owner);
    println!("A3g: {members} members: largest value {name} {largest} B, checkpoint tree {tree} B");
    let provider = arachne_runtime::SqliteProvider::new(directory.path(), root);
    arachne_runtime::harness::seed_workspace(&provider, &owner, None, None).unwrap();
    let workspace = owner.id();
    drop(owner);

    // Every stored record fits; long values are split into parts.
    let store =
        arachne_store::Store::open_existing(&provider.path(workspace), &root, workspace).unwrap();
    let names: Vec<Vec<u8>> = store.keys(b"").map(<[u8]>::to_vec).collect();
    let largest_stored = names
        .iter()
        .map(|name| store.get(name).unwrap().unwrap().len())
        .max()
        .unwrap();
    let parts = names
        .iter()
        .filter(|name| name.windows(6).any(|w| w == b"\x00part/"))
        .count();
    println!(
        "A3g: {members} members: {} stored records, {parts} parts, largest {largest_stored} B",
        names.len()
    );
    assert!(largest_stored <= MAX_RECORD_BYTES);
    if largest > 512 * 1024 {
        assert!(parts > 0, "a value over 512 KiB must be saved in parts");
    }
    drop(store);

    let handle = arachne_runtime::create(Some(&secret)).unwrap();
    arachne_runtime::attach_storage(
        handle,
        arachne_runtime::StorageConfig::sqlite(directory.path(), root),
    )
    .unwrap();
    let restored = call(handle, json!({"op":"restore_workspace","workspace":workspace}));
    assert_eq!(restored["members"], members);
    // A staged change at this size saves (as parts) and adopts.
    let staged = call(handle, json!({"op":"stage_workspace_name","workspace_name":"Large"}));
    let adopted = call(handle, json!({"op":"adopt_admission","candidate":staged["candidate"]}));
    assert_eq!(adopted["workspace_name"], "Large");
    arachne_runtime::close(handle).unwrap();
    let handle = arachne_runtime::create(Some(&secret)).unwrap();
    arachne_runtime::attach_storage(
        handle,
        arachne_runtime::StorageConfig::sqlite(directory.path(), root),
    )
    .unwrap();
    let restored = call(handle, json!({"op":"restore_workspace","workspace":workspace}));
    assert_eq!(restored["workspace_name"], "Large");
    assert_eq!(restored["members"], members);
    arachne_runtime::close(handle).unwrap();
    directory.close().unwrap();
    members
}

#[test]
fn fixed_bound_records_fit_one_store_record() {
    // The delivery attachment and a pending join (with its B3a checkpoint)
    // are each one record; an invitation checkpoint record holds a grant and
    // one checkpoint.
    assert!(MAX_WORKSPACE_ATTACHMENT <= MAX_RECORD_BYTES);
    assert!(MAX_SEALED_PENDING_JOIN <= MAX_RECORD_BYTES);
    assert!(1024 + MAX_CHECKPOINT <= MAX_RECORD_BYTES);
}

#[test]
#[ignore = "heavy: builds 513 members in a debug build (about 8 minutes); run it explicitly"]
fn the_largest_value_grows_past_one_record_and_is_saved_in_parts() {
    // Growth per member of the largest value, projected to the roster where
    // the checkpoint tree reaches its bound.
    let signer = EndpointKey::generate().unwrap();
    let small = grown(Workspace::create(&signer, "Measure").unwrap(), MAX_ADMISSION_BATCH + 1);
    let (members_a, _, largest_a, tree_a) = measure(&small);
    let large = grown(small, 2 * MAX_ADMISSION_BATCH + 1);
    let (members_b, _, largest_b, tree_b) = measure(&large);
    let added = members_b - members_a;
    let record_per_member = (largest_b - largest_a).div_ceil(added);
    let tree_per_member = (tree_b - tree_a) / added;
    let bound_members = members_b + (MAX_CHECKPOINT_TREE - tree_b) / tree_per_member;
    let projected = largest_b + record_per_member * (bound_members - members_b);
    println!(
        "A3g: ~{record_per_member} B per member; at the checkpoint bound (~{bound_members} members) the largest value is ~{projected} B; the record limit is {MAX_RECORD_BYTES} B"
    );
    assert!(projected > MAX_RECORD_BYTES, "measurement changed; revisit the split");
    drop(large);
    assert!(saves_stages_and_restores_at(4 * MAX_ADMISSION_BATCH + 1) > 512);
}

/// At least 2,000 members: save, stage, adopt and restore; and the size of
/// one Add at that roster against the joiner's history cap. Run with
/// `cargo test --release -p arachne-runtime --test record_bounds -- --ignored two_thousand`.
#[test]
#[ignore = "release mode: builds 2,049 members; run it explicitly with --release"]
fn two_thousand_members_save_stage_and_restore() {
    let size = 16 * MAX_ADMISSION_BATCH + 1;
    assert!(saves_stages_and_restores_at(size) >= 2000);
    // The joiner replays history steps under MAX_JOIN_HISTORY_BYTES. Measure
    // one single Add and one full batch Add at this roster.
    let signer = EndpointKey::generate().unwrap();
    let owner = grown(Workspace::create(&signer, "History").unwrap(), size);
    let (registration, invitation, checkpoint) = owner.prepare_invitation(0, false, false).unwrap();
    let owner = registration.workspace;
    let one = [EndpointKey::generate().unwrap()];
    let single = owner
        .prepare_validated_admission_batch(&batch(&owner, &invitation, &checkpoint, &one))
        .unwrap()
        .commit
        .len();
    let keys: Vec<_> = (0..MAX_ADMISSION_BATCH)
        .map(|_| EndpointKey::generate().unwrap())
        .collect();
    let full = owner
        .prepare_validated_admission_batch(&batch(&owner, &invitation, &checkpoint, &keys))
        .unwrap()
        .commit
        .len();
    println!(
        "A3g history at {} members: one Add {single} B ({} fit {MAX_JOIN_HISTORY_BYTES} B); a batch of {MAX_ADMISSION_BATCH} Adds {full} B ({} fit)",
        owner.member_count(),
        MAX_JOIN_HISTORY_BYTES / single,
        MAX_JOIN_HISTORY_BYTES / full,
    );
}
