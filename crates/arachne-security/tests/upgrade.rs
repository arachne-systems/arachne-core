//! Built-in provider compatibility only; no application migration layer.
//! The fixture was generated offline using OpenMLS 0.8.1 and synthetic keys.
use arachne_security::{PendingJoin, StorageKey, Workspace};
use std::path::PathBuf;

const CONTEXT: &[u8] = b"security-upgrade regression";
const PAYLOAD: &[u8] = b"message prepared before the provider upgrade";

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/openmls-0.8.1.fixture")
}

#[test]
#[ignore = "Run only with OpenMLS 0.8.1 to create the immutable synthetic fixture"]
fn generate_old_provider_fixture() {
    assert!(include_str!("../Cargo.toml").contains("openmls = \"=0.8.1\""));
    let admin = Workspace::create_named([1; 32], "Upgrade Admin", Some("Upgrade Test")).unwrap();
    let (invite, checkpoint) = admin.issue_invitation().unwrap();
    let pending =
        PendingJoin::from_invitation(&invite, &checkpoint, [2; 32], "Upgrade Member").unwrap();
    let prepared = admin
        .prepare_admission([2; 32], pending.admission_request().unwrap())
        .unwrap();
    let mut proof = pending.join_proof().unwrap();
    proof
        .apply_add(&prepared.authorization, &prepared.commit)
        .unwrap();
    let receiver = pending
        .prepare_workspace(&proof, &prepared.welcome)
        .unwrap();
    let mut sender = prepared.workspace;
    let packet = sender.protect_application(CONTEXT, PAYLOAD).unwrap();
    let mut bytes = sender.id().to_vec();
    for blob in [
        sender
            .seal(&StorageKey::derive(&[11; 32]).unwrap())
            .unwrap(),
        receiver
            .seal(&StorageKey::derive(&[22; 32]).unwrap())
            .unwrap(),
        packet,
    ] {
        bytes.extend(u32::try_from(blob.len()).unwrap().to_be_bytes());
        bytes.extend(blob);
    }
    std::fs::create_dir_all(fixture_path().parent().unwrap()).unwrap();
    // A new fixture must not overwrite the original pre-upgrade evidence.
    use std::io::Write;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(fixture_path())
        .unwrap()
        .write_all(&bytes)
        .unwrap();
}

#[test]
fn old_json_provider_state_continues_messaging_and_replay_protection() {
    let fixture = include_bytes!("data/openmls-0.8.1.fixture");
    let id: [u8; 32] = fixture[..32].try_into().unwrap();
    let mut remaining = &fixture[32..];
    let mut blob = || {
        let count = u32::from_be_bytes(remaining[..4].try_into().unwrap()) as usize;
        let result = remaining[4..4 + count].to_vec();
        remaining = &remaining[4 + count..];
        result
    };
    let sender_state = blob();
    let receiver_state = blob();
    let old_packet = blob();
    assert!(remaining.is_empty());
    let sender_key = StorageKey::derive(&[11; 32]).unwrap();
    let receiver_key = StorageKey::derive(&[22; 32]).unwrap();
    let mut sender = Workspace::restore(&sender_key, [1; 32], id, &sender_state).unwrap();
    let mut receiver = Workspace::restore(&receiver_key, [2; 32], id, &receiver_state).unwrap();
    assert_eq!(sender.member_count(), 2);
    assert_eq!(
        sender.workspace_name().unwrap().as_deref(),
        Some("Upgrade Test")
    );
    assert_eq!(sender.member().unwrap().display_name(), "Upgrade Admin");
    assert_eq!(receiver.member().unwrap().display_name(), "Upgrade Member");
    assert_eq!(sender.epoch_fingerprint(), receiver.epoch_fingerprint());
    let message = receiver
        .unprotect_application(CONTEXT, &old_packet)
        .unwrap();
    assert_eq!(message.payload, PAYLOAD);
    assert_eq!(message.endpoint, [1; 32]);
    let received_state = receiver.seal(&receiver_key).unwrap();
    let mut replay = Workspace::restore(&receiver_key, [2; 32], id, &received_state).unwrap();
    assert!(replay.unprotect_application(CONTEXT, &old_packet).is_err());
    // A failed receive may advance provisional ratchets: discard that owner.
    let mut receiver = Workspace::restore(&receiver_key, [2; 32], id, &received_state).unwrap();
    let reply = receiver
        .protect_application(CONTEXT, b"message after upgrade")
        .unwrap();
    assert_eq!(
        sender
            .unprotect_application(CONTEXT, &reply)
            .unwrap()
            .payload,
        b"message after upgrade"
    );
    let records = sender.export_records().unwrap();
    let restored = Workspace::restore_records([1; 32], id, &records).unwrap();
    assert_eq!(restored.epoch_fingerprint(), sender.epoch_fingerprint());
}
