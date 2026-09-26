//! Real security/store composition; no network or fixture routing policy.
use arachne_security::{MembershipVerifier, PendingJoin, SecurityRecords, StorageKey, Workspace};
use arachne_store::{Change, Store};

mod common;

fn save(store: &mut Store, owner: &Workspace) {
    let records = owner.export_records().unwrap();
    let mut changed = Vec::new();
    for (name, value) in &records {
        if store.get(name).unwrap().as_deref() != Some(value.as_ref()) {
            changed.push((name.as_slice(), Some(value.as_slice())));
        }
    }
    let deleted: Vec<_> = store
        .keys(b"security/")
        .filter(|name| !records.contains_key(*name))
        .map(<[u8]>::to_vec)
        .collect();
    let changes: Vec<Change<'_>> = changed
        .into_iter()
        .chain(deleted.iter().map(|name| (name.as_slice(), None)))
        .collect();
    store.commit(store.revision(), &changes).unwrap();
    for (name, value) in changes {
        assert!(
            store
                .get(name)
                .unwrap()
                .as_ref()
                .map(|bytes| bytes.as_slice())
                == value
        );
    }
}

fn restore(store: &Store, endpoint: [u8; 32], workspace: [u8; 32]) -> Workspace {
    let records: SecurityRecords = store
        .keys(b"security/")
        .map(|name| (name.to_vec(), store.get(name).unwrap().unwrap()))
        .collect();
    Workspace::restore_records(endpoint, workspace, &records).unwrap()
}

/// Pre-release rule: no legacy formats. A version-one record set is
/// refused with the one "create the workspace again" error.
#[test]
fn restores_version_one_security_records() {
    let key = arachne_security::EndpointKey::generate().unwrap();
    let owner = Workspace::create(&key, "Legacy record owner").unwrap();
    let mut records = owner.export_records().unwrap();
    let meta = records.get_mut(b"security/meta".as_slice()).unwrap();
    meta[..5].copy_from_slice(b"DFWR\x01");
    let legacy_length = meta.len() - 8;
    meta.truncate(legacy_length);
    assert_eq!(
        Workspace::restore_records(owner.endpoint(), owner.id(), &records).err(),
        Some(arachne_security::FORMAT_NOT_SUPPORTED)
    );
}

#[test]
fn hundred_members_save_as_records_and_follower_crosses_old_history_ceiling() {
    let directory = common::directory();
    let admin_key = arachne_security::EndpointKey::generate().unwrap();
    let mut admin = Workspace::create(&admin_key, "Record-store administrator").unwrap();
    let id = admin.id();
    let admin_endpoint = admin.endpoint();
    let old_key = StorageKey::derive(&[201; 32]).unwrap();
    let old_file = admin.seal(&old_key).unwrap();
    admin = Workspace::restore(&old_key, admin_endpoint, id, &old_file).unwrap();
    let member_keys: Vec<_> = (0..100)
        .map(|_| arachne_security::EndpointKey::generate().unwrap())
        .collect();
    let late_key = arachne_security::EndpointKey::generate().unwrap();
    let late_endpoint = arachne_security::EndpointSigner::endpoint(&late_key);
    let first_member = arachne_security::EndpointSigner::endpoint(&member_keys[1]);
    let (registered, old_invitation, old_checkpoint) = admin.prepare_invitation(0, false, false).unwrap();
    admin = registered.workspace;
    let admin_path = directory.path().join("admin.db");
    let follower_path = directory.path().join("follower.db");
    let mut admin_store = Store::open(&admin_path, &[202; 32], id).unwrap();
    let mut follower_store = Store::open(&follower_path, &[203; 32], id).unwrap();
    save(&mut admin_store, &admin);
    let mut follower: Option<Workspace> = None;
    let mut latest = None;
    for member in 1u8..100 {
        let (registered, invite, checkpoint) = admin.prepare_invitation(0, false, false).unwrap();
        admin = registered.workspace;
        if let Some(owner) = &follower {
            // The follower is already a member once one exists, so it must
            // apply the registration commit too or it forks from admin.
            let updated = owner
                .prepare_management_update(registered.action, &registered.commit)
                .unwrap();
            let arachne_security::PreparedManagementUpdate::Active(boxed) = updated else {
                panic!("expected active update")
            };
            follower = Some(*boxed);
        }
        let member_key = &member_keys[member as usize];
        let pending =
            PendingJoin::from_invitation(&invite, &checkpoint, member_key, "Workspace member")
                .unwrap();
        let prepared = admin
            .prepare_admission(
                arachne_security::EndpointSigner::endpoint(member_key),
                pending.admission_request().unwrap(),
            )
            .unwrap();
        let mut proof = pending.join_proof().unwrap();
        proof
            .apply_add(&prepared.authorization, &prepared.commit)
            .unwrap();
        let joined = pending
            .prepare_workspace(&proof, &prepared.welcome)
            .unwrap();
        let next_follower = match &follower {
            Some(owner) => Workspace::prepare_admission_update(
                owner,
                &prepared.authorization,
                &prepared.commit,
            )
            .unwrap(),
            None => joined,
        };
        save(&mut admin_store, &prepared.workspace);
        save(&mut follower_store, &next_follower);
        admin = prepared.workspace;
        follower = Some(next_follower);
        if member == 99 {
            // The final joiner independently validates the persisted branch below.
            latest = Some((pending, proof, prepared.welcome));
        }
        if [16, 64, 99].contains(&member) {
            drop(admin_store);
            drop(follower_store);
            admin_store = Store::open(&admin_path, &[202; 32], id).unwrap();
            follower_store = Store::open(&follower_path, &[203; 32], id).unwrap();
            admin = restore(&admin_store, admin_endpoint, id);
            follower = Some(restore(&follower_store, first_member, id));
            println!(
                "reopened members={} admin_records={} follower_records={}",
                admin.member_count(),
                admin_store.keys(b"security/").count(),
                follower_store.keys(b"security/").count()
            );
        }
    }
    assert_eq!(admin.member_count(), 100);
    assert_eq!(follower.as_ref().unwrap().member_count(), 100);
    assert!(admin.seal(&old_key).is_err()); // Legacy format must not silently truncate.
    assert!(follower.as_ref().unwrap().seal(&old_key).is_err());
    let (pending, proof, welcome) = latest.unwrap();
    let joined = pending.prepare_workspace(&proof, &welcome).unwrap();
    assert!(proof.matches_workspace(&admin).unwrap());
    // An invitation from the founding epoch still has verifiable retained history.
    let late =
        PendingJoin::from_invitation(&old_invitation, &old_checkpoint, &late_key, "Later joiner")
            .unwrap();
    let steps = admin
        .membership_history(
            late_endpoint,
            late.admission_request().unwrap(),
            &old_checkpoint,
        )
        .unwrap();
    // 99 -> 198: each of the 99 loop iterations now also registers its
    // invitation via prepare_invitation before admitting, costing one extra
    // epoch per member on top of the admission commit itself.
    assert_eq!(steps.len(), 198);
    let mut verifier = MembershipVerifier::from_trusted_checkpoint(
        id,
        old_invitation.checkpoint_digest(),
        &old_checkpoint,
    )
    .unwrap();
    for (auth, commit) in steps {
        verifier.apply_transition(&auth, &commit).unwrap();
    }
    assert!(verifier.matches_workspace(&admin).unwrap());
    let sample = admin
        .protect_object(b"streams", b"streams/opaque", b"one hundred members")
        .unwrap();
    save(&mut admin_store, &admin); // Persist the sender counter before delivery.
    for reader in [follower.as_ref().unwrap(), &joined] {
        assert!(reader.unprotect_object(b"streams", b"streams/opaque", &sample).is_ok());
    }
    // Native storage metadata is scope-bound; missing provider state fails closed.
    let mut records = admin.export_records().unwrap();
    assert!(Workspace::restore_records([199; 32], id, &records).is_err());
    let provider_key = records
        .keys()
        .find(|name| name.starts_with(b"security/provider/"))
        .unwrap()
        .clone();
    records.remove(&provider_key);
    assert!(Workspace::restore_records(admin_endpoint, id, &records).is_err());
    drop(admin_store);
    drop(follower_store);
    directory.close().unwrap();
}
