//! Bounded author-authenticated coverage offers. No retrieval or ratchet mutation.
use super::{
    ApplicationMessage, MAX_APPLICATION_CIPHERTEXT, MAX_APPLICATION_CONTEXT,
    MAX_APPLICATION_PAYLOAD, SUITE, Workspace, bootstrap,
};
use openmls_traits::{
    OpenMlsProvider, crypto::OpenMlsCrypto, random::OpenMlsRand, signatures::Signer,
};
use sha2::{Digest, Sha256};

const DOMAIN: &[u8] = b"data-fabric/recovery-offer/v1\0";
const CURRENT_VIEW_DOMAIN: &[u8] = b"data-fabric/current-view-statement/v1\0";
const SIGNATURE_BYTES: usize = 64;
pub const MAX_RECOVERY_PACKETS: usize = 32;

/// A locally established request, not values copied from an untrusted offer.
/// The caller supplies a canonical selection digest and obtains
/// the exclusive/inclusive range from its durable delivery cursor/index.
#[derive(Clone, Debug)]
pub struct RecoveryRequest {
    pub workspace: [u8; 32],
    pub author: [u8; 32],
    pub epoch: u64,
    pub selection: [u8; 32],
    pub after: u64,
    pub through: u64,
}
impl RecoveryRequest {
    fn header(&self) -> Result<Vec<u8>, &'static str> {
        if self.after >= self.through {
            return Err("invalid recovery request");
        }
        let mut bytes = DOMAIN.to_vec();
        bytes.extend(self.workspace);
        bytes.extend(self.author);
        bytes.extend(self.epoch.to_be_bytes());
        bytes.extend(self.selection);
        bytes.extend(self.after.to_be_bytes());
        bytes.extend(self.through.to_be_bytes());
        Ok(bytes)
    }
}

/// Locally generated request for a current publisher index head. A fresh nonce
/// binds the response to this exchange; it is not a durable coverage cursor.
#[derive(Clone, Debug)]
pub struct RecoveryCutoffRequest {
    pub workspace: [u8; 32],
    pub author: [u8; 32],
    pub epoch: u64,
    pub selection: [u8; 32],
    pub policy_revision: u64,
    pub nonce: [u8; 32],
}
impl RecoveryCutoffRequest {
    fn header(&self) -> Vec<u8> {
        let mut bytes = b"data-fabric/recovery-cutoff/v2\0".to_vec();
        bytes.extend(self.workspace);
        bytes.extend(self.author);
        bytes.extend(self.epoch.to_be_bytes());
        bytes.extend(self.selection);
        bytes.extend(self.policy_revision.to_be_bytes());
        bytes.extend(self.nonce);
        bytes
    }
}

fn digest(context: &[u8], ciphertext: &[u8]) -> Result<[u8; 32], &'static str> {
    if context.len() > MAX_APPLICATION_CONTEXT
        || ciphertext.is_empty()
        || ciphertext.len() > MAX_APPLICATION_CIPHERTEXT
    {
        return Err("recovery packet exceeds bounds");
    }
    let mut hash = Sha256::new();
    hash.update(b"data-fabric/recovery-packet/v1\0");
    hash.update((context.len() as u32).to_be_bytes());
    hash.update(context);
    hash.update((ciphertext.len() as u32).to_be_bytes());
    hash.update(ciphertext);
    Ok(hash.finalize().into())
}

/// Authenticated offer for exactly one request. Still not proof that the author's
/// own retained index is complete/honest, nor permission to release plaintext.
pub struct VerifiedRecoveryOffer<'a> {
    _membership: &'a Workspace,
    author: [u8; 32],
    endpoint: [u8; 32],
    packets: Vec<[u8; 32]>,
}
impl VerifiedRecoveryOffer<'_> {
    /// Check the entire ordered response BEFORE decrypting/advancing live state.
    /// The caller reconstructs canonical contexts, never trusts incoming MLS AAD.
    pub fn verify_packets(&self, packets: &[(&[u8], &[u8])]) -> Result<(), &'static str> {
        if packets.len() != self.packets.len() {
            return Err("incomplete recovery response");
        }
        for ((context, ciphertext), expected) in packets.iter().zip(&self.packets) {
            if &digest(context, ciphertext)? != expected {
                return Err("recovery packet or order mismatch");
            }
        }
        Ok(())
    }
    /// Each decrypted packet must ALSO have this authenticated origin. A valid
    /// offer cannot turn another member's ciphertext into this author's traffic.
    pub fn verify_origin(&self, message: &ApplicationMessage) -> Result<(), &'static str> {
        if message.member != self.author || message.endpoint != self.endpoint {
            return Err("recovery author mismatch");
        }
        Ok(())
    }
}

impl Workspace {
    /// Sign current-view metadata without advancing application encryption state.
    /// The encrypted transport still controls who can obtain the statement.
    pub fn sign_current_view(&self, context: &[u8], body: &[u8]) -> Result<Vec<u8>, &'static str> {
        if self.member.is_none()
            || context.len() > MAX_APPLICATION_CONTEXT
            || body.len() > MAX_APPLICATION_PAYLOAD
        {
            return Err("current-view statement exceeds bounds or lacks member identity");
        }
        let signature = self
            ._signer
            .sign(&current_view_statement(context, body))
            .map_err(|_| "current-view signing failed")?;
        let mut signed = body.to_vec();
        signed.extend(signature);
        Ok(signed)
    }

    /// Verify the statement against one current workspace member selected by the
    /// locally established query. Authorization to request it is checked outside.
    pub fn verify_current_view<'a>(
        &self,
        authority: [u8; 32],
        context: &[u8],
        signed: &'a [u8],
    ) -> Result<&'a [u8], &'static str> {
        if context.len() > MAX_APPLICATION_CONTEXT
            || !(SIGNATURE_BYTES..=MAX_APPLICATION_PAYLOAD + SIGNATURE_BYTES)
                .contains(&signed.len())
        {
            return Err("invalid current-view statement size");
        }
        let end = signed.len() - SIGNATURE_BYTES;
        let (_, key) = self.recovery_signer(authority)?;
        self.provider
            .crypto()
            .verify_signature(
                SUITE.signature_algorithm(),
                &current_view_statement(context, &signed[..end]),
                &key,
                &signed[end..],
            )
            .map_err(|_| "invalid current-view signature")?;
        Ok(&signed[..end])
    }

    /// Build a caller-owned discovery request from an accepted peer credential.
    /// Fresh randomness is generated locally; never accept a network-supplied nonce.
    pub fn recovery_cutoff_request(
        &self,
        peer: [u8; 32],
        selection: [u8; 32],
        policy_revision: u64,
    ) -> Result<RecoveryCutoffRequest, &'static str> {
        Ok(RecoveryCutoffRequest {
            workspace: self.id(),
            author: self.member_id_for_endpoint(peer)?,
            epoch: self.epoch(),
            selection,
            policy_revision,
            nonce: self
                .provider
                .rand()
                .random_array::<32>()
                .map_err(|_| "recovery randomness failed")?,
        })
    }

    /// Resolve a workspace-facing endpoint through the current accepted roster.
    pub fn member_id_for_endpoint(&self, peer: [u8; 32]) -> Result<[u8; 32], &'static str> {
        let mut author = None;
        for member in self.group.members() {
            let (id, endpoint) = bootstrap::binding(&member.credential)?;
            if endpoint == peer {
                if author.is_some() {
                    return Err("ambiguous recovery endpoint");
                }
                author = Some(id);
            }
        }
        author.ok_or("recovery peer is not a current member")
    }

    /// Caller authorizes the requester and reads the head from adopted retention
    /// state. A head identifies a cutoff only, never complete or available history.
    pub fn sign_recovery_cutoff(
        &self,
        request: &RecoveryCutoffRequest,
        head: u64,
    ) -> Result<Vec<u8>, &'static str> {
        self.sign_recovery_window(request, 0, head)
    }

    /// Signed retention boundary for the requested selection, not delivery coverage.
    pub fn sign_recovery_window(
        &self,
        request: &RecoveryCutoffRequest,
        after: u64,
        head: u64,
    ) -> Result<Vec<u8>, &'static str> {
        if after > head {
            return Err("invalid recovery window");
        }
        if request.workspace != self.id()
            || request.epoch != self.epoch()
            || self.member().map(|m| m.id()) != Some(request.author)
        {
            return Err("invalid recovery cutoff scope");
        }
        let mut bytes = request.header();
        bytes.extend(after.to_be_bytes());
        bytes.extend(head.to_be_bytes());
        let signature = self
            ._signer
            .sign(&bytes)
            .map_err(|_| "recovery signing failed")?;
        bytes.extend(signature);
        Ok(bytes)
    }

    /// Verify current membership, caller-held nonce/selection/policy and exact
    /// framing before exposing the head. The caller consumes its nonce once;
    /// replaying the same request cannot establish another freshness observation.
    pub fn verify_recovery_cutoff(
        &self,
        expected: &RecoveryCutoffRequest,
        bytes: &[u8],
    ) -> Result<u64, &'static str> {
        self.verify_recovery_window(expected, bytes)
            .map(|(_, head)| head)
    }

    pub fn verify_recovery_window(
        &self,
        expected: &RecoveryCutoffRequest,
        bytes: &[u8],
    ) -> Result<(u64, u64), &'static str> {
        if self.member().is_none()
            || expected.workspace != self.id()
            || expected.epoch != self.epoch()
        {
            return Err("wrong recovery workspace or epoch");
        }
        let header = expected.header();
        if bytes.len() != header.len() + 16 + 64 || !bytes.starts_with(&header) {
            return Err("invalid recovery cutoff request or size");
        }
        let (_, key) = self.recovery_signer(expected.author)?;
        let end = bytes.len() - 64;
        self.provider
            .crypto()
            .verify_signature(
                SUITE.signature_algorithm(),
                &bytes[..end],
                &key,
                &bytes[end..],
            )
            .map_err(|_| "invalid recovery cutoff signature")?;
        let after = u64::from_be_bytes(bytes[header.len()..header.len() + 8].try_into().unwrap());
        let head = u64::from_be_bytes(bytes[header.len() + 8..end].try_into().unwrap());
        if after > head {
            return Err("invalid recovery window");
        }
        Ok((after, head))
    }

    fn recovery_signer(&self, author: [u8; 32]) -> Result<([u8; 32], Vec<u8>), &'static str> {
        let mut signer = None;
        for member in self.group.members() {
            let (id, endpoint) = bootstrap::binding(&member.credential)?;
            if id == author {
                if signer.is_some() {
                    return Err("ambiguous recovery author");
                }
                signer = Some((endpoint, member.signature_key));
            }
        }
        signer.ok_or("recovery author is not a current member")
    }

    /// Sign the exact packet set selected by this author's retained index. The
    /// host must establish coverage independently; this method cannot infer it
    /// from ciphertext. No claim of current/latest coverage beyond the request.
    /// Offers expose metadata and require an authorized encrypted channel.
    pub fn sign_recovery_offer(
        &self,
        request: &RecoveryRequest,
        packets: &[(&[u8], &[u8])],
    ) -> Result<Vec<u8>, &'static str> {
        if request.workspace != self.id()
            || request.epoch != self.epoch()
            || self.member().map(|m| m.id()) != Some(request.author)
            || packets.len() > MAX_RECOVERY_PACKETS
        {
            return Err("invalid recovery offer scope or size");
        }
        let mut bytes = request.header()?;
        bytes.extend((packets.len() as u16).to_be_bytes());
        let mut unique = std::collections::BTreeSet::new();
        for (context, ciphertext) in packets {
            let value = digest(context, ciphertext)?;
            if !unique.insert(value) {
                return Err("duplicate recovery packet");
            }
            bytes.extend(value);
        }
        let signature = self
            ._signer
            .sign(&bytes)
            .map_err(|_| "recovery signing failed")?;
        bytes.extend(signature);
        Ok(bytes)
    }

    /// Verify against current accepted membership and a locally established
    /// request. Signature checks do not authorize topic access or old epochs.
    pub fn verify_recovery_offer<'a>(
        &'a self,
        expected: &RecoveryRequest,
        bytes: &[u8],
    ) -> Result<VerifiedRecoveryOffer<'a>, &'static str> {
        if self.member().is_none()
            || expected.workspace != self.id()
            || expected.epoch != self.epoch()
        {
            return Err("wrong recovery workspace or epoch");
        }
        let header = expected.header()?;
        if bytes.len() < header.len() + 2 + 64
            || bytes.len() > header.len() + 2 + 32 * MAX_RECOVERY_PACKETS + 64
            || !bytes.starts_with(&header)
        {
            return Err("invalid recovery offer request or size");
        }
        let count =
            u16::from_be_bytes(bytes[header.len()..header.len() + 2].try_into().unwrap()) as usize;
        let end = header.len() + 2 + 32 * count;
        if count > MAX_RECOVERY_PACKETS || bytes.len() != end + 64 {
            return Err("invalid recovery offer count");
        }
        let (endpoint, key) = self.recovery_signer(expected.author)?;
        self.provider
            .crypto()
            .verify_signature(
                SUITE.signature_algorithm(),
                &bytes[..end],
                &key,
                &bytes[end..],
            )
            .map_err(|_| "invalid recovery offer signature")?;
        let packets = bytes[header.len() + 2..end].as_chunks::<32>().0.to_vec();
        if packets
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != packets.len()
        {
            return Err("duplicate recovery digest");
        }
        Ok(VerifiedRecoveryOffer {
            _membership: self,
            author: expected.author,
            endpoint,
            packets,
        })
    }
}

fn current_view_statement(context: &[u8], body: &[u8]) -> Vec<u8> {
    let mut bytes = CURRENT_VIEW_DOMAIN.to_vec();
    bytes.extend((context.len() as u32).to_be_bytes());
    bytes.extend(context);
    bytes.extend((body.len() as u32).to_be_bytes());
    bytes.extend(body);
    bytes
}

#[test]
fn recovery_offer_authenticates_request_and_exact_packet_set() {
    use crate::{PendingJoin, StorageKey};
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
    let receiver = pending
        .prepare_workspace(&proof, &prepared.welcome)
        .unwrap();
    let mut sender = prepared.workspace;
    let key = StorageKey::derive(&[9; 32]).unwrap();
    let before = receiver.seal(&key).unwrap();
    let first_request = receiver
        .recovery_cutoff_request(sender.endpoint(), [4; 32], 7)
        .unwrap();
    let next_request = receiver
        .recovery_cutoff_request(sender.endpoint(), [4; 32], 7)
        .unwrap();
    assert_eq!(first_request.author, sender.member().unwrap().id());
    assert_ne!(first_request.nonce, next_request.nonce);
    assert!(
        receiver
            .recovery_cutoff_request([99; 32], [4; 32], 7)
            .is_err()
    );
    let reply = sender.sign_recovery_cutoff(&first_request, 52).unwrap();
    assert!(
        receiver
            .verify_recovery_cutoff(&next_request, &reply)
            .is_err()
    );
    let cutoff = RecoveryCutoffRequest {
        workspace: sender.id(),
        author: sender.member().unwrap().id(),
        epoch: sender.epoch(),
        selection: [4; 32],
        policy_revision: 7,
        nonce: [5; 32],
    };
    let window = sender.sign_recovery_window(&cutoff, 32, 52).unwrap();
    assert_eq!(
        receiver.verify_recovery_window(&cutoff, &window).unwrap(),
        (32, 52)
    );
    assert!(sender.sign_recovery_window(&cutoff, 53, 52).is_err());
    let mut changed_window = window.clone();
    changed_window[cutoff.header().len()] ^= 1;
    assert!(
        receiver
            .verify_recovery_window(&cutoff, &changed_window)
            .is_err()
    );
    for head in [0, 1, 52, u64::MAX] {
        let bytes = sender.sign_recovery_cutoff(&cutoff, head).unwrap();
        assert_eq!(
            receiver.verify_recovery_cutoff(&cutoff, &bytes).unwrap(),
            head
        );
        for cut in 0..bytes.len() {
            assert!(
                receiver
                    .verify_recovery_cutoff(&cutoff, &bytes[..cut])
                    .is_err()
            );
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(receiver.verify_recovery_cutoff(&cutoff, &trailing).is_err());
        for offset in [cutoff.header().len(), bytes.len() - 1] {
            let mut damaged = bytes.clone();
            damaged[offset] ^= 1;
            assert!(receiver.verify_recovery_cutoff(&cutoff, &damaged).is_err());
        }
        for field in 0..6 {
            let mut changed = cutoff.clone();
            match field {
                0 => changed.workspace[0] ^= 1,
                1 => changed.author[0] ^= 1,
                2 => changed.epoch += 1,
                3 => changed.selection[0] ^= 1,
                4 => changed.policy_revision += 1,
                _ => changed.nonce[0] ^= 1,
            }
            assert!(receiver.verify_recovery_cutoff(&changed, &bytes).is_err());
        }
        // Another admitted member cannot impersonate the requested author.
        let mut forged = bytes[..bytes.len() - 64].to_vec();
        let signature = receiver._signer.sign(&forged).unwrap();
        forged.extend(signature);
        assert!(receiver.verify_recovery_cutoff(&cutoff, &forged).is_err());
    }
    assert!(receiver.sign_recovery_cutoff(&cutoff, 52).is_err());
    let mut ciphertexts = Vec::new();
    for value in [b"first".as_slice(), b"second"] {
        ciphertexts.push(
            sender
                .protect_application(b"opaque context", value)
                .unwrap(),
        );
        let _saved_sender = sender.seal(&key).unwrap();
    }
    let packets: Vec<_> = ciphertexts
        .iter()
        .map(|p| (b"opaque context".as_slice(), p.as_slice()))
        .collect();
    let request = RecoveryRequest {
        workspace: sender.id(),
        author: sender.member().unwrap().id(),
        epoch: sender.epoch(),
        selection: [4; 32],
        after: 1,
        through: 3,
    };
    let encoded = sender.sign_recovery_offer(&request, &packets).unwrap();
    assert!(receiver.verify_recovery_cutoff(&cutoff, &encoded).is_err());
    assert!(
        receiver
            .verify_recovery_offer(&request, &sender.sign_recovery_cutoff(&cutoff, 52).unwrap())
            .is_err()
    );
    let verified = receiver.verify_recovery_offer(&request, &encoded).unwrap();
    verified.verify_packets(&packets).unwrap();
    assert!(verified.verify_packets(&packets[..1]).is_err());
    assert!(verified.verify_packets(&[packets[1], packets[0]]).is_err());
    assert!(verified.verify_packets(&[packets[0], packets[0]]).is_err());
    assert!(
        verified
            .verify_packets(&[(b"wrong context".as_slice(), packets[0].1), packets[1]])
            .is_err()
    );
    let mut damaged_packet = ciphertexts[0].clone();
    damaged_packet[0] ^= 1;
    assert!(
        verified
            .verify_packets(&[(packets[0].0, damaged_packet.as_slice()), packets[1]])
            .is_err()
    );
    for offset in [0, encoded.len() - 65, encoded.len() - 1] {
        let mut damaged = encoded.clone();
        damaged[offset] ^= 1;
        assert!(receiver.verify_recovery_offer(&request, &damaged).is_err());
    }
    let mut forged = encoded[..encoded.len() - 64].to_vec();
    let signature = receiver._signer.sign(&forged).unwrap();
    forged.extend(signature);
    assert!(receiver.verify_recovery_offer(&request, &forged).is_err());
    let mut invalid_count = encoded.clone();
    let offset = request.header().unwrap().len();
    invalid_count[offset..offset + 2].copy_from_slice(&0u16.to_be_bytes());
    assert!(
        receiver
            .verify_recovery_offer(&request, &invalid_count)
            .is_err()
    );
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(receiver.verify_recovery_offer(&request, &trailing).is_err());
    assert!(
        receiver
            .verify_recovery_offer(&request, &encoded[..encoded.len() - 1])
            .is_err()
    );
    for field in 0..6 {
        let mut wrong = request.clone();
        match field {
            0 => wrong.workspace[0] ^= 1,
            1 => wrong.author[0] ^= 1,
            2 => wrong.epoch += 1,
            3 => wrong.selection[0] ^= 1,
            4 => wrong.after = 0,
            _ => wrong.through += 1,
        }
        assert!(receiver.verify_recovery_offer(&wrong, &encoded).is_err());
    }
    assert!(receiver.sign_recovery_offer(&request, &packets).is_err());
    let outsider = Workspace::create([5; 32], "Outsider").unwrap();
    assert!(outsider.verify_recovery_offer(&request, &encoded).is_err());
    let empty = sender.sign_recovery_offer(&request, &[]).unwrap();
    let verified_empty = receiver.verify_recovery_offer(&request, &empty).unwrap();
    verified_empty.verify_packets(&[]).unwrap();
    assert!(verified_empty.verify_packets(&packets).is_err());
    assert!(
        sender
            .sign_recovery_offer(&request, &[packets[0]; MAX_RECOVERY_PACKETS + 1])
            .is_err()
    );
    assert!(
        sender
            .sign_recovery_offer(&request, &[packets[0]; 2])
            .is_err()
    );
    assert!(sender.sign_recovery_offer(&request, &[(b"", b"")]).is_err());
    assert!(
        sender
            .sign_recovery_offer(&request, &[(&[0; MAX_APPLICATION_CONTEXT + 1], b"x")])
            .is_err()
    );
    assert!(
        sender
            .sign_recovery_offer(&request, &[(b"", &[0; MAX_APPLICATION_CIPHERTEXT + 1])])
            .is_err()
    );
    let mut invalid = request.clone();
    invalid.through = invalid.after;
    assert!(sender.sign_recovery_offer(&invalid, &packets).is_err());
    let mut candidate = Workspace::restore(&key, [2; 32], receiver.id(), &before).unwrap();
    for (context, packet) in &packets {
        let mut message = candidate.unprotect_application(context, packet).unwrap();
        verified.verify_origin(&message).unwrap();
        message.endpoint = [8; 32];
        assert!(verified.verify_origin(&message).is_err());
        message.endpoint = [1; 32];
        message.member = [8; 32];
        assert!(verified.verify_origin(&message).is_err());
    }
    let saved = candidate.seal(&key).unwrap();
    let mut restored = Workspace::restore(&key, [2; 32], receiver.id(), &saved).unwrap();
    assert!(
        restored
            .unprotect_application(packets[0].0, packets[0].1)
            .is_err()
    );
    // A signature attests the author's claim, not correctness of its index.
    // The library cannot detect an author deliberately signing an incomplete set.
    let incomplete = sender.sign_recovery_offer(&request, &packets[1..]).unwrap();
    receiver
        .verify_recovery_offer(&request, &incomplete)
        .unwrap()
        .verify_packets(&packets[1..])
        .unwrap();
    drop(sender); // Retained offers require no fresh challenge to an online author.
    receiver
        .verify_recovery_offer(&request, &encoded)
        .unwrap()
        .verify_packets(&packets)
        .unwrap();
}
