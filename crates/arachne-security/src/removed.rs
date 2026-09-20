//! Protected local record of accepted removal. Contains no group traffic keys,
//! private signing state, retained publications or invitation capabilities.
use crate::{MemberProfile, StorageKey, storage};
use openmls_rust_crypto::OpenMlsRustCrypto;
use zeroize::Zeroizing;

const MAGIC: &[u8; 5] = b"DFRM\x01";
const SOLO: &[u8; 5] = b"DFRM\x02";
pub const MAX_SEALED_REMOVAL: usize = 5 + 32 + 12 + 16 + 8 + 32 + 4 + 256 + 32;

/// An accepted removal's local metadata. Verified management reception or the sole member ending a workspace can
/// create this value; it exposes no active Workspace operations.
#[derive(Debug, PartialEq, Eq)]
pub struct RemovedMembership {
    workspace: [u8; 32],
    endpoint: [u8; 32],
    member: MemberProfile,
    epoch: u64,
    commit_digest: [u8; 32],
    solo: bool,
}

impl RemovedMembership {
    pub(super) fn verified(
        workspace: [u8; 32],
        endpoint: [u8; 32],
        member: MemberProfile,
        epoch: u64,
        commit_digest: [u8; 32],
    ) -> Self {
        Self {
            workspace,
            endpoint,
            member,
            epoch,
            commit_digest,
            solo: false,
        }
    }
    pub(super) fn for_solo_leave(mut self) -> Self {
        self.solo = true;
        self
    }

    pub fn workspace_id(&self) -> [u8; 32] {
        self.workspace
    }
    pub fn endpoint(&self) -> [u8; 32] {
        self.endpoint
    }
    pub fn member(&self) -> &MemberProfile {
        &self.member
    }
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    pub fn commit_digest(&self) -> [u8; 32] {
        self.commit_digest
    }

    /// Atomically replace the active snapshot with this record before reporting
    /// removal or dropping the live owner. Host backup rollback is not prevented.
    pub fn seal(&self, key: &StorageKey) -> Result<Vec<u8>, &'static str> {
        let mut plain = Zeroizing::new(self.epoch.to_be_bytes().to_vec());
        storage::write_profile(&mut plain, &self.member);
        plain.extend(self.commit_digest);
        key.protect(
            &OpenMlsRustCrypto::default(),
            if self.solo { SOLO } else { MAGIC },
            self.workspace,
            self.endpoint,
            &plain,
        )
    }

    /// Reopening a removed record yields only removal metadata, never keys or an
    /// active member. Wrong-family/corrupt records must not trigger fallback.
    pub fn restore(
        key: &StorageKey,
        endpoint: [u8; 32],
        workspace: [u8; 32],
        sealed: &[u8],
    ) -> Result<Self, &'static str> {
        if sealed.len() > MAX_SEALED_REMOVAL {
            return Err("removed membership exceeds bounds");
        }
        let solo = sealed.starts_with(SOLO);
        let plain = key.unprotect(if solo { SOLO } else { MAGIC }, workspace, endpoint, sealed)?;
        let mut bytes = plain.as_slice();
        let epoch = u64::from_be_bytes(storage::take(&mut bytes, 8)?.try_into().unwrap());
        let member = storage::read_profile(&mut bytes)?;
        let commit_digest = storage::take(&mut bytes, 32)?.try_into().unwrap();
        if (!solo && epoch == 0) || member.id() == [0; 32] || !bytes.is_empty() {
            return Err("invalid removed membership metadata");
        }
        let mut record = Self::verified(workspace, endpoint, member, epoch, commit_digest);
        record.solo = solo;
        Ok(record)
    }
}
