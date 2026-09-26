//! ADR A1 open point: no secret goes into an error.
//!
//! Scope: secrets the runtime holds (the endpoint secret, sealed snapshots,
//! invitation bytes and keys). The deprecated JSON dispatcher's decode errors
//! can echo the caller's own request text back to that caller; that is not
//! covered here.

use arachne_runtime::{
    Client, ClientConfig, ApiError, FreshnessAnchor, MemoryProvider, Network, StorageConfig,
};
use base64::Engine;

const SECRET: [u8; 32] = [0xA7; 32];

fn open(secret: [u8; 32], provider: &MemoryProvider) -> std::sync::Arc<Client> {
    Client::open(ClientConfig {
        network: Network::Direct,
        secret: Some((secret).into()),
        transport: Default::default(),
        storage: Some((StorageConfig::memory(provider)).into()),
    })
    .unwrap()
}

fn tampered(bytes: &[u8]) -> Vec<u8> {
    let mut bytes = bytes.to_vec();
    let middle = bytes.len() / 2;
    bytes[middle] ^= 0x5A;
    bytes
}

/// Every 8-byte window of `secret` in the forms an error could print it.
fn renderings(secret: &[u8]) -> Vec<String> {
    let mut forms = Vec::new();
    for window in secret.windows(8) {
        let lower: String = window.iter().map(|b| format!("{b:02x}")).collect();
        forms.push(lower.to_uppercase());
        forms.push(lower);
        let decimal: Vec<String> = window.iter().map(u8::to_string).collect();
        forms.push(decimal.join(", "));
        forms.push(decimal.join(","));
    }
    if secret.len() >= 12 {
        let encoded = base64::engine::general_purpose::STANDARD.encode(secret);
        forms.push(encoded[..16].to_owned());
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(secret);
        forms.push(encoded[..16].to_owned());
    }
    forms
}

fn assert_no_secret(error: &ApiError, secrets: &[(&str, &[u8])]) {
    let texts = [
        error.message().to_owned(),
        format!("{error}"),
        format!("{error:?}"),
        serde_json::to_string(error).unwrap(),
    ];
    for (name, secret) in secrets {
        for form in renderings(secret) {
            for text in &texts {
                assert!(
                    !text.contains(&form),
                    "error text shows part of the {name}: {text}"
                );
            }
        }
    }
}

#[test]
fn errors_from_secret_inputs_do_not_show_the_secret() {
    let provider = MemoryProvider::default();
    let mut owner = open(SECRET, &provider);
    let created = owner.create_workspace("Owner", None).unwrap();
    let anchor = owner.record_freshness().unwrap();
    let candidate = owner.stage_invitation(0).unwrap();
    let invitation = owner.adopt_invitation(&candidate).unwrap();

    let other_provider = MemoryProvider::default();
    let mut other = open([0x3C; 32], &other_provider);
    let mut errors = Vec::new();
    // This session's storage never saved anything for this workspace.
    errors.extend(other.restore_workspace(created.workspace, None).err());
    // A damaged freshness anchor against the owner's own storage.
    let mut owner_again = open(SECRET, &provider);
    let damaged = FreshnessAnchor::from_bytes(&tampered(&anchor.to_bytes())).unwrap();
    errors.extend(
        owner_again
            .restore_workspace(created.workspace, Some(damaged))
            .err(),
    );
    // A damaged invitation, and a damaged checkpoint.
    errors.extend(
        other
            .inspect_invitation(&tampered(&invitation.invitation), &invitation.checkpoint)
            .err(),
    );
    errors.extend(
        other
            .inspect_invitation(&invitation.invitation, &tampered(&invitation.checkpoint))
            .err(),
    );
    // A candidate that was already used.
    errors.extend(owner.adopt_invitation(&candidate).err());
    assert!(
        errors.len() >= 4,
        "expected most secret inputs to fail, got {} errors",
        errors.len()
    );

    let secrets: [(&str, &[u8]); 3] = [
        ("endpoint secret", &SECRET),
        ("invitation", &invitation.invitation),
        ("invitation key", invitation.invitation_key.as_bytes()),
    ];
    for error in &errors {
        assert_no_secret(error, &secrets);
    }
    other.close().unwrap();
    owner_again.close().unwrap();
    owner.close().unwrap();
}
