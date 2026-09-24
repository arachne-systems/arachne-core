//! A members-only key that names this workspace's gossip overlay.
//!
//! The creator draws 32 random bytes once. Each Add carries them to its
//! joiners inside the Welcome's encrypted GroupInfo, never in the group
//! context (handshakes are public and `join_checkpoint` publishes GroupInfo).
//! The key never changes, so all members at any epoch derive the same tag.
//! A removed member keeps it; the tag hides the workspace from network
//! observers and is not access control (the data plane is gated on policy).
use super::Workspace;
use openmls::prelude::*;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{OpenMlsProvider, random::OpenMlsRand};

/// Provider storage label. Seal, restore and record export carry it.
const LABEL: &[u8] = b"arachne/gossip-tag-key/v1";
/// Private GroupInfo extension that carries the key in a Welcome.
const EXTENSION: u16 = 0xff02;

/// Draw a new key and store it with a new workspace's state.
pub(super) fn generate(provider: &OpenMlsRustCrypto) -> Result<(), &'static str> {
    let key = provider
        .rand()
        .random_array::<32>()
        .map_err(|_| "gossip key randomness failed")?;
    store(provider, key)
}

fn store(provider: &OpenMlsRustCrypto, key: [u8; 32]) -> Result<(), &'static str> {
    provider
        .storage()
        .values
        .write()
        .map_err(|_| "storage unavailable")?
        .insert(LABEL.to_vec(), key.to_vec());
    Ok(())
}

fn load(provider: &OpenMlsRustCrypto) -> Result<[u8; 32], &'static str> {
    provider
        .storage()
        .values
        .read()
        .map_err(|_| "storage unavailable")?
        .get(LABEL)
        .ok_or("workspace has no gossip key")?
        .as_slice()
        .try_into()
        .map_err(|_| "invalid gossip key")
}

/// The GroupInfo extension for an Add's Welcome. Only the Welcome copy is
/// sent; the exported GroupInfo of the same commit must be discarded.
pub(super) fn welcome_extension(provider: &OpenMlsRustCrypto) -> Result<Extension, &'static str> {
    Ok(Extension::Unknown(
        EXTENSION,
        UnknownExtension(load(provider)?.to_vec()),
    ))
}

/// Add `packages` without a path update, as `add_members_without_update`
/// does, with the key in the Welcome. Returns the commit and the Welcome;
/// the exported GroupInfo, which would carry the key in the clear, is dropped.
#[cfg(test)]
pub(super) fn add_members(
    group: &mut MlsGroup,
    provider: &OpenMlsRustCrypto,
    signer: &openmls_basic_credential::SignatureKeyPair,
    packages: Vec<KeyPackage>,
) -> Result<(MlsMessageOut, MlsMessageOut), &'static str> {
    if packages.is_empty() {
        return Err("admission preparation failed");
    }
    let bundle = group
        .commit_builder()
        .propose_adds(packages)
        .force_self_update(false)
        .load_psks(provider.storage())
        .map_err(|_| "admission preparation failed")?
        .create_group_info_with_extensions([welcome_extension(provider)?])
        .map_err(|_| "admission preparation failed")?
        .build(provider.rand(), provider.crypto(), signer, |_| true)
        .map_err(|_| "admission preparation failed")?
        .stage_commit(provider)
        .map_err(|_| "admission preparation failed")?;
    let (commit, welcome, _exported_group_info) = bundle.into_messages();
    Ok((commit, welcome.ok_or("admission produced no Welcome")?))
}

/// Take the key from a Welcome's GroupInfo and store it for the joiner.
/// Call only after the Welcome has been validated. No key: fail closed.
pub(super) fn adopt(
    provider: &OpenMlsRustCrypto,
    group_info: &Extensions<openmls::messages::group_info::GroupInfo>,
) -> Result<(), &'static str> {
    let key = group_info
        .iter()
        .find_map(|extension| match extension {
            Extension::Unknown(EXTENSION, UnknownExtension(bytes)) => Some(bytes),
            _ => None,
        })
        .ok_or("Welcome carries no gossip key")?
        .as_slice()
        .try_into()
        .map_err(|_| "invalid gossip key")?;
    store(provider, key)
}

impl Workspace {
    /// The stable, members-only key for this workspace's gossip overlay tag.
    pub fn gossip_tag_key(&self) -> Result<[u8; 32], &'static str> {
        load(&self.provider)
    }
}

#[cfg(test)]
mod tests {
    use super::super::{PendingJoin, StorageKey, Workspace};
    use openmls::prelude::{tls_codec::Deserialize, *};
    use openmls_traits::OpenMlsProvider;

    fn admit(
        by: &Workspace,
        invitation: &super::super::Invitation,
        checkpoint: &[u8],
        endpoint: [u8; 32],
    ) -> (Workspace, Workspace) {
        let pending =
            PendingJoin::from_invitation(invitation, checkpoint, endpoint, "Joiner").unwrap();
        let mut proof = pending.join_proof().unwrap();
        let prepared = by
            .prepare_admission(endpoint, pending.admission_request().unwrap())
            .unwrap();
        proof
            .apply_add(&prepared.authorization, &prepared.commit)
            .unwrap();
        let joined = pending
            .prepare_workspace(&proof, &prepared.welcome)
            .unwrap();
        (prepared.workspace, joined)
    }

    #[test]
    fn every_member_shares_one_stable_secret_key() {
        let admin = Workspace::create([1; 32], "Coordinator").unwrap();
        let key = admin.gossip_tag_key().unwrap();
        assert_ne!(key, admin.id());
        assert_ne!(
            key,
            Workspace::create([1; 32], "Other")
                .unwrap()
                .gossip_tag_key()
                .unwrap()
        );
        // Public group state never carries it.
        let checkpoint = admin.join_checkpoint().unwrap();
        assert!(!checkpoint.windows(32).any(|window| window == key));

        // A registration commit changes the epoch, not the key.
        let (registration, invitation, checkpoint) =
            admin.prepare_invitation(0, false, false).unwrap();
        let admin = registration.workspace;
        assert_eq!(admin.gossip_tag_key().unwrap(), key);
        let (admin, helper) = admit(&admin, &invitation, &checkpoint, [2; 32]);
        assert_eq!(helper.gossip_tag_key().unwrap(), key);
        assert_eq!(
            admin.gossip_tag_key().unwrap(),
            key,
            "a commit changed the key"
        );

        // A third member admitted by the second, not the issuer, gets it too.
        let (registration, invitation, checkpoint) =
            admin.prepare_invitation(0, false, false).unwrap();
        let super::super::PreparedManagementUpdate::Active(helper) = helper
            .prepare_management_update(registration.action, &registration.commit)
            .unwrap()
        else {
            panic!("registration removed the helper")
        };
        let (helper, third) = admit(&helper, &invitation, &checkpoint, [3; 32]);
        assert_eq!(third.gossip_tag_key().unwrap(), key);
        assert_eq!(helper.gossip_tag_key().unwrap(), key);

        // Seal/restore and record export/restore keep it.
        let storage = StorageKey::derive(&[7; 32]).unwrap();
        let sealed = third.seal(&storage).unwrap();
        let restored = Workspace::restore(&storage, [3; 32], third.id(), &sealed).unwrap();
        assert_eq!(restored.gossip_tag_key().unwrap(), key);
        let records = restored.export_records().unwrap();
        let restored = Workspace::restore_records([3; 32], third.id(), &records).unwrap();
        assert_eq!(restored.gossip_tag_key().unwrap(), key);
    }

    #[test]
    fn a_welcome_without_the_key_fails_closed() {
        let admin = Workspace::create([1; 32], "Coordinator").unwrap();
        let (registration, invitation, checkpoint) =
            admin.prepare_invitation(0, false, false).unwrap();
        let admin = registration.workspace;
        let pending =
            PendingJoin::from_invitation(&invitation, &checkpoint, [2; 32], "Joiner").unwrap();
        let proof = pending.join_proof().unwrap();
        // An issuer whose state lost the key cannot produce a keyless Add.
        admin
            .provider
            .storage()
            .values
            .write()
            .unwrap()
            .remove(super::LABEL);
        assert_eq!(
            admin
                .prepare_admission([2; 32], pending.admission_request().unwrap())
                .err(),
            Some("workspace has no gossip key")
        );
        // A Welcome built without it is refused by the joiner, before any
        // other check could accept the rest of the join.
        let mut group = admin.provisional_copy().unwrap();
        let (_, welcome, _) = group
            .group
            .add_members_without_update(
                &group.provider,
                &group._signer,
                &[
                    KeyPackageIn::tls_deserialize_exact(pending.key_package().unwrap())
                        .unwrap()
                        .validate(group.provider.crypto(), ProtocolVersion::Mls10)
                        .unwrap(),
                ],
            )
            .unwrap();
        let welcome = welcome.to_bytes().unwrap();
        assert_eq!(
            pending.prepare_workspace(&proof, &welcome).err(),
            Some("Welcome carries no gossip key")
        );
    }
}
