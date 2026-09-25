//! A3g: every record the runtime saves fits the store's 1 MiB record limit
//! at the member counts the security bounds allow.
//!
//! Native storage saves a workspace as many records, not one sealed bundle:
//! the MLS provider values, retained admissions, join history and invitation
//! checkpoints (`security/*`), the object inbox with the publisher log
//! (`delivery/inbox`), and a pending join (`runtime/pending`). The inbox and
//! the pending join have fixed bounds. The records that grow with the roster
//! are measured at two sizes and projected to the largest roster that the
//! invitation checkpoint bound (`MAX_CHECKPOINT_TREE`) admits; past it no
//! invitation checkpoint can be issued, so no one else can join.
use arachne_security::{
    AdmissionAssessment, MAX_ADMISSION_BATCH, MAX_CHECKPOINT, MAX_CHECKPOINT_TREE,
    MAX_SEALED_PENDING_JOIN, MAX_WORKSPACE_ATTACHMENT, PendingJoin, Workspace,
};
use arachne_store::MAX_RECORD_BYTES;

mod common;

fn synthetic(index: usize) -> [u8; 32] {
    let mut value = [0; 32];
    value[..8].copy_from_slice(&(index as u64 + 1).to_be_bytes());
    value[8..16].copy_from_slice(&(!(index as u64)).to_be_bytes());
    value
}

/// An owner at `endpoint` with `size` or more members, admitted in batches.
fn grown(owner: Workspace, size: usize, next: &mut usize) -> Workspace {
    let (registration, invitation, checkpoint) = owner.prepare_invitation(0, false, false).unwrap();
    let mut owner = registration.workspace;
    while owner.member_count() < size {
        let range = *next..(*next + MAX_ADMISSION_BATCH);
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
        *next = range.end;
    }
    owner
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
        String::from_utf8_lossy(name).into_owned(),
        value.len(),
        tree,
    )
}

#[test]
#[ignore = "heavy: builds 513 members in a debug build (about 8 minutes); run it explicitly"]
fn every_saved_record_fits_one_store_record_at_the_member_bound() {
    // Fixed bounds: the delivery attachment and a pending join (with its
    // B3a checkpoint) are each one record.
    assert!(MAX_WORKSPACE_ATTACHMENT <= MAX_RECORD_BYTES);
    assert!(MAX_SEALED_PENDING_JOIN <= MAX_RECORD_BYTES);
    // An invitation checkpoint record holds a grant and one checkpoint.
    assert!(1024 + MAX_CHECKPOINT <= MAX_RECORD_BYTES);

    let directory = common::directory();
    let root = [8; 32];
    let handle = arachne_runtime::create(Some(&[7; 32])).unwrap();
    let described: serde_json::Value =
        serde_json::from_str(&arachne_runtime::describe(handle).unwrap()).unwrap();
    let endpoint: [u8; 32] = serde_json::from_value(described["endpoint_key"].clone()).unwrap();

    let mut next = 0;
    let owner = Workspace::create(endpoint, "Record bound owner").unwrap();
    let small = grown(owner, MAX_ADMISSION_BATCH + 1, &mut next);
    let (members_a, name_a, largest_a, tree_a) = measure(&small);
    let large = grown(small, 2 * MAX_ADMISSION_BATCH + 1, &mut next);
    let (members_b, name_b, largest_b, tree_b) = measure(&large);
    println!("A3g: {members_a} members: largest record {name_a:.40} {largest_a} B, tree {tree_a} B");
    println!("A3g: {members_b} members: largest record {name_b:.40} {largest_b} B, tree {tree_b} B");

    // Linear growth per member, projected to the roster where the checkpoint
    // tree reaches its bound. The MLS provider keeps its tree as JSON, about
    // 4.7 times the wire tree, so the largest value there is several MiB:
    // more than one store record.
    let added = members_b - members_a;
    let record_per_member = (largest_b - largest_a).div_ceil(added);
    let tree_per_member = (tree_b - tree_a) / added;
    assert!(tree_per_member > 0);
    let bound_members = members_b + (MAX_CHECKPOINT_TREE - tree_b) / tree_per_member;
    let projected = largest_b + record_per_member * (bound_members - members_b);
    println!(
        "A3g: at the checkpoint bound (~{bound_members} members) the largest value is ~{projected} B; the store limit is {MAX_RECORD_BYTES} B"
    );
    assert!(projected > MAX_RECORD_BYTES, "measurement changed; revisit the split");

    // So the runtime saves long values as parts. A roster whose largest value
    // is past the part size saves, every stored record fits, and it restores.
    let owner = grown(large, 4 * MAX_ADMISSION_BATCH + 1, &mut next);
    let (members_c, _, largest_c, _) = measure(&owner);
    println!("A3g: {members_c} members: largest value {largest_c} B");
    assert!(largest_c > 512 * 1024, "the value must span parts");
    let provider = arachne_runtime::SqliteProvider::new(directory.path(), root);
    arachne_runtime::harness::seed_workspace(&provider, &owner, None, None).unwrap();
    let path = provider.path(owner.id());
    let store = arachne_store::Store::open_existing(&path, &root, owner.id()).unwrap();
    let names: Vec<Vec<u8>> = store.keys(b"").map(<[u8]>::to_vec).collect();
    let largest_stored = names
        .iter()
        .map(|name| store.get(name).unwrap().unwrap().len())
        .max()
        .unwrap();
    assert!(largest_stored <= MAX_RECORD_BYTES);
    assert!(names.iter().any(|name| name.windows(6).any(|w| w == b"\x00part/")));
    drop(store);
    arachne_runtime::attach_storage(
        handle,
        arachne_runtime::StorageConfig::sqlite(directory.path(), root),
    )
    .unwrap();
    let restored: serde_json::Value = serde_json::from_slice(
        &arachne_runtime::execute(
            handle,
            &serde_json::to_vec(&serde_json::json!({"op":"restore_workspace","workspace":owner.id()}))
                .unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(restored["members"], members_c);
    arachne_runtime::close(handle).unwrap();
    directory.close().unwrap();
}
