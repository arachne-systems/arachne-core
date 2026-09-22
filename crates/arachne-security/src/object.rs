//! Signed, independently decryptable current-epoch objects. Delivery owns replay
//! records and application handoff; successful authentication is not delivery.
use super::{
    ApplicationMessage, MAX_APPLICATION_CIPHERTEXT, MAX_APPLICATION_CONTEXT,
    MAX_APPLICATION_PAYLOAD, SUITE, Workspace, bootstrap,
};
use openmls_traits::{OpenMlsProvider, crypto::OpenMlsCrypto, signatures::Signer};
use sframe::{
    CipherSuite,
    frame::{EncryptedFrameView, MediaFrameView, MonotonicCounter},
    key::{DecryptionKey, EncryptionKey},
};
use zeroize::Zeroizing;

const MAGIC: &[u8] = b"DFSO\x01";
const HEADER: usize = 5 + 32 + 8 + 4;
const SIGNATURE: usize = 64;
const DOMAIN: &[u8] = b"data-fabric/signed-object/v1\0";
// A namespaced application record in the already persisted provider snapshot.
// It is not an OpenMLS storage key or a second uncommitted state store.
const COUNTER: &[u8] = b"data-fabric/object-sender-counter/v1\0";
const CIPHER: CipherSuite = CipherSuite::AesGcm256Sha512;

#[derive(Debug, PartialEq, Eq)]
pub struct AuthenticatedObject {
    pub message: ApplicationMessage,
    /// Scoped to the authenticated author and current workspace epoch.
    pub counter: u64,
}

#[test]
fn objects_are_independent_authenticated_and_current_epoch_only() {
    use super::{PendingJoin, StorageKey};
    let admin = Workspace::create([1; 32], "Publisher").unwrap();
    let (invite, checkpoint) = admin.issue_invitation().unwrap();
    let pending = PendingJoin::from_invitation(&invite, &checkpoint, [2; 32], "Reader").unwrap();
    let prepared = admin
        .prepare_admission([2; 32], pending.admission_request().unwrap())
        .unwrap();
    let mut proof = pending.join_proof().unwrap();
    proof
        .apply_add(&prepared.authorization, &prepared.commit)
        .unwrap();
    let mut reader = pending
        .prepare_workspace(&proof, &prepared.welcome)
        .unwrap();
    let mut sender = prepared.workspace;
    let storage_key = StorageKey::derive(&[11; 32]).unwrap();
    let old = sender
        .protect_object(b"chat/first", b"retained chat")
        .unwrap();
    let size = sender.seal(&storage_key).unwrap().len();
    for _ in 0..10_000 {
        sender.protect_object(b"feed", b"opaque sample").unwrap();
    }
    let live = sender.protect_object(b"chat/latest", b"live chat").unwrap();
    assert_eq!(
        reader
            .unprotect_object(b"chat/latest", &live)
            .unwrap()
            .counter,
        10_002
    );
    let first = reader.unprotect_object(b"chat/first", &old).unwrap();
    assert_eq!(first.counter, 1);
    assert_eq!(first.message.payload, b"retained chat");
    assert_eq!(first.message.endpoint, sender.endpoint());
    assert_eq!(first.message.member, sender.member().unwrap().id());
    assert_eq!(size, sender.seal(&storage_key).unwrap().len());
    // No ratchet/replay side effects in crypto; delivery must suppress repeats.
    assert_eq!(reader.unprotect_object(b"chat/first", &old).unwrap(), first);
    assert!(reader.unprotect_object(b"feed", &old).is_err());
    let outsider = Workspace::create([3; 32], "Other workspace").unwrap();
    assert!(outsider.unprotect_object(b"chat/first", &old).is_err());
    for offset in [0, 5, 37, 45, HEADER, old.len() - 1] {
        let mut changed = old.clone();
        changed[offset] ^= 1;
        assert!(reader.unprotect_object(b"chat/first", &changed).is_err());
    }
    let mut forged = old.clone();
    let end = forged.len() - SIGNATURE;
    let signature = reader
        ._signer
        .sign(&signed(b"chat/first", &forged[..end]))
        .unwrap();
    forged[end..].copy_from_slice(&signature);
    assert_eq!(
        reader.unprotect_object(b"chat/first", &forged).unwrap_err(),
        "object signature invalid"
    );
    for len in 0..old.len() {
        assert!(reader.unprotect_object(b"chat/first", &old[..len]).is_err());
    }
    assert!(
        sender
            .protect_object(&vec![0; MAX_APPLICATION_CONTEXT + 1], b"")
            .is_err()
    );
    assert!(
        sender
            .protect_object(b"", &vec![0; MAX_APPLICATION_PAYLOAD + 1])
            .is_err()
    );
    let maximum = sender
        .protect_object(b"max", &vec![7; MAX_APPLICATION_PAYLOAD])
        .unwrap();
    assert_eq!(
        reader
            .unprotect_object(b"max", &maximum)
            .unwrap()
            .message
            .payload
            .len(),
        MAX_APPLICATION_PAYLOAD
    );
    let saved = sender.seal(&storage_key).unwrap();
    sender = Workspace::restore(&storage_key, sender.endpoint(), sender.id(), &saved).unwrap();
    let next = sender.protect_object(b"after-restore", b"chat").unwrap();
    assert_eq!(
        reader
            .unprotect_object(b"after-restore", &next)
            .unwrap()
            .counter,
        10_004
    );

    // Accepted removal closes the old epoch for both live and catch-up objects.
    sender
        .group
        .remove_members(
            &sender.provider,
            &sender._signer,
            &[reader.group.own_leaf_index()],
        )
        .unwrap();
    sender.group.merge_pending_commit(&sender.provider).unwrap();
    let backdated = reader
        .protect_object(b"old-claim", b"manufactured after removal")
        .unwrap();
    assert_eq!(
        sender
            .unprotect_object(b"old-claim", &backdated)
            .unwrap_err(),
        "object epoch not current"
    );
    assert_eq!(
        sender.unprotect_object(b"chat/first", &old).unwrap_err(),
        "object epoch not current"
    );
    let fresh = sender
        .protect_object(b"new-epoch", b"private to current members")
        .unwrap();
    assert_eq!(
        sender
            .unprotect_object(b"new-epoch", &fresh)
            .unwrap()
            .counter,
        1
    );
    assert!(reader.unprotect_object(b"new-epoch", &fresh).is_err());

    let epoch = sender.epoch();
    sender.provider.storage().values.write().unwrap().insert(
        COUNTER.to_vec(),
        [epoch.to_be_bytes(), u64::MAX.to_be_bytes()].concat(),
    );
    assert_eq!(
        sender.protect_object(b"", b"").unwrap_err(),
        "object counter exhausted"
    );
    sender
        .provider
        .storage()
        .values
        .write()
        .unwrap()
        .insert(COUNTER.to_vec(), vec![0]);
    let malformed = sender.seal(&storage_key).unwrap();
    assert!(Workspace::restore(&storage_key, sender.endpoint(), sender.id(), &malformed).is_err());
}

fn signed(context: &[u8], object: &[u8]) -> Vec<u8> {
    [
        DOMAIN,
        &(context.len() as u32).to_be_bytes(),
        context,
        object,
    ]
    .concat()
}

fn key_id(epoch: u64, leaf: u32) -> u64 {
    // RFC9605 5.2, E=16 and context=0; no other context is accepted. Since
    // context=0, S does not affect the encoding. Only one epoch is retained.
    (u64::from(leaf) << 16) | (epoch & 0xffff)
}

impl Workspace {
    fn object_secret(&self) -> Result<Zeroizing<Vec<u8>>, &'static str> {
        self.group
            .export_secret(self.provider.crypto(), "SFrame 1.0 Base Key", b"", 32)
            .map(Zeroizing::new)
            .map_err(|_| "object key unavailable")
    }

    pub(super) fn object_counter(&self) -> Result<u64, &'static str> {
        let state = self
            .provider
            .storage()
            .values
            .read()
            .map_err(|_| "storage unavailable")?;
        let Some(value) = state.get(COUNTER) else {
            return Ok(0);
        };
        if value.len() != 16 {
            return Err("invalid object counter state");
        }
        let epoch = u64::from_be_bytes(value[..8].try_into().unwrap());
        let counter = u64::from_be_bytes(value[8..].try_into().unwrap());
        if epoch > self.epoch() || counter == 0 {
            return Err("invalid object counter state");
        }
        Ok(if epoch == self.epoch() { counter } else { 0 })
    }

    /// Host MUST durably save the resulting owner before releasing this object.
    /// Retries resend the exact object. Never restore an older committed sender
    /// state to retry encryption. On error discard the candidate, as with MLS.
    pub fn protect_object(
        &mut self,
        context: &[u8],
        payload: &[u8],
    ) -> Result<Vec<u8>, &'static str> {
        if self.member.is_none()
            || context.len() > MAX_APPLICATION_CONTEXT
            || payload.len() > MAX_APPLICATION_PAYLOAD
        {
            return Err("object exceeds bounds or lacks member identity");
        }
        let counter = self
            .object_counter()?
            .checked_add(1)
            .ok_or("object counter exhausted")?;
        let epoch = self.epoch();
        let leaf = self.group.own_leaf_index().u32();
        let secret = self.object_secret()?;
        let key = EncryptionKey::derive_from(CIPHER, key_id(epoch, leaf), secret.as_slice())
            .map_err(|_| "object key unavailable")?;
        let mut nonce = MonotonicCounter::with_start_value(counter, counter);
        let frame = MediaFrameView::with_meta_data(&mut nonce, payload, context)
            .encrypt(&key)
            .map_err(|_| "object encryption failed")?;
        let mut object = MAGIC.to_vec();
        object.extend(self.id());
        object.extend(epoch.to_be_bytes());
        object.extend(leaf.to_be_bytes());
        // Owning SFrame buffers include metadata; our caller reconstructs it.
        object.extend(&frame.as_ref()[frame.meta_data().len()..]);
        object.extend(
            self._signer
                .sign(&signed(context, &object))
                .map_err(|_| "object signing failed")?,
        );
        if object.len() > MAX_APPLICATION_CIPHERTEXT {
            return Err("object exceeds bounds");
        }
        self.provider
            .storage()
            .values
            .write()
            .map_err(|_| "storage unavailable")?
            .insert(
                COUNTER.to_vec(),
                [epoch.to_be_bytes(), counter.to_be_bytes()].concat(),
            );
        Ok(object)
    }

    /// Authenticate using the CURRENT accepted epoch/roster only. Does not import
    /// historical epochs, mutate a ratchet or suppress replay. The delivery layer
    /// must atomically record acceptance and pending application work before use.
    pub fn unprotect_object(
        &self,
        context: &[u8],
        object: &[u8],
    ) -> Result<AuthenticatedObject, &'static str> {
        if context.len() > MAX_APPLICATION_CONTEXT
            || !(HEADER + 2 + 16 + SIGNATURE..=MAX_APPLICATION_CIPHERTEXT).contains(&object.len())
            || !object.starts_with(MAGIC)
            || object[5..37] != self.id()
        {
            return Err("invalid object envelope");
        }
        let epoch = u64::from_be_bytes(object[37..45].try_into().unwrap());
        if epoch != self.epoch() {
            return Err("object epoch not current");
        }
        let leaf = u32::from_be_bytes(object[45..HEADER].try_into().unwrap());
        let author = self
            .group
            .members()
            .find(|member| member.index.u32() == leaf)
            .ok_or("object author not current");
        let author = author?;
        let (member, endpoint) = bootstrap::binding(&author.credential)?;
        let (body, signature) = object.split_at(object.len() - SIGNATURE);
        self.provider
            .crypto()
            .verify_signature(
                SUITE.signature_algorithm(),
                &signed(context, body),
                &author.signature_key,
                signature,
            )
            .map_err(|_| "object signature invalid")?;
        let frame = EncryptedFrameView::try_with_meta_data(&body[HEADER..], context)
            .map_err(|_| "invalid encrypted object")?;
        if frame.header().key_id() != key_id(epoch, leaf) || frame.header().counter() == 0 {
            return Err("object key or counter mismatch");
        }
        let secret = self.object_secret()?;
        let key = DecryptionKey::derive_from(CIPHER, key_id(epoch, leaf), secret.as_slice())
            .map_err(|_| "object key unavailable")?;
        let plain = frame
            .decrypt(&key)
            .map_err(|_| "object authentication failed")?;
        if plain.payload().len() > MAX_APPLICATION_PAYLOAD {
            return Err("object payload exceeds bounds");
        }
        Ok(AuthenticatedObject {
            counter: frame.header().counter(),
            message: ApplicationMessage {
                member,
                endpoint,
                payload: plain.payload().to_vec(),
            },
        })
    }
}
