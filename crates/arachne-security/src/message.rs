//! MLS application protection, independent of transport and payload format.
use super::*;
use openmls::prelude::tls_codec::Deserialize;

pub const MAX_APPLICATION_PAYLOAD: usize = 12 * 1024;
pub const MAX_APPLICATION_CONTEXT: usize = 1024;
pub const MAX_APPLICATION_CIPHERTEXT: usize = 16 * 1024;

/// Authenticated origin, not necessarily the immediate transport peer.
#[derive(Debug, PartialEq, Eq)]
pub struct ApplicationMessage {
    pub member: [u8; 32],
    pub endpoint: [u8; 32],
    pub payload: Vec<u8>,
}

impl Workspace {
    /// Advances the sender ratchet. The host must persist the updated workspace
    /// before sending the returned ciphertext or preparing another publication.
    /// On any error, close this owner and restore its last committed snapshot.
    /// Retrying delivery uses the SAME ciphertext, never re-encryption from old state.
    pub fn protect_application(
        &mut self,
        context: &[u8],
        payload: &[u8],
    ) -> Result<Vec<u8>, &'static str> {
        if self.member.is_none()
            || payload.len() > MAX_APPLICATION_PAYLOAD
            || context.len() > MAX_APPLICATION_CONTEXT
        {
            return Err("application publication exceeds bounds or lacks member identity");
        }
        self.group.set_aad(context.to_vec());
        let encrypted = self
            .group
            .create_message(&self.provider, &self._signer, payload)
            .map_err(|_| "application encryption failed")?
            .to_bytes()
            .map_err(|_| "application encoding failed")?;
        if encrypted.len() > MAX_APPLICATION_CIPHERTEXT {
            return Err("application ciphertext exceeds bounds");
        }
        Ok(encrypted)
    }

    /// Authenticates an application message and advances replay/receive state.
    /// The host must persist before delivering the returned plaintext. On any
    /// error discard this owner and restore committed state: rejection can occur
    /// after the library has consumed a receive-ratchet generation.
    /// Context must be the canonical expected routing envelope, not an unchecked
    /// copy of the incoming message's AAD. This does not grant topic permissions.
    pub fn unprotect_application(
        &mut self,
        context: &[u8],
        ciphertext: &[u8],
    ) -> Result<ApplicationMessage, &'static str> {
        if context.len() > MAX_APPLICATION_CONTEXT || ciphertext.len() > MAX_APPLICATION_CIPHERTEXT
        {
            return Err("application message exceeds bounds");
        }
        let message = MlsMessageIn::tls_deserialize_exact(ciphertext)
            .map_err(|_| "invalid application encoding")?;
        // Membership handshakes have their own authorization path. Never process
        // public proposals/commits as application traffic.
        let MlsMessageBodyIn::PrivateMessage(message) = message.extract() else {
            return Err("application message must be private");
        };
        let processed = self
            .group
            .process_message(&self.provider, message)
            .map_err(|_| "application authentication or replay check failed")?;
        if processed.aad() != context {
            return Err("application routing context mismatch");
        }
        let credential = BasicCredential::try_from(processed.credential().clone())
            .map_err(|_| "unsupported application author")?;
        let identity = credential
            .identity()
            .strip_prefix(b"data-fabric/candidate-member/v2/")
            .filter(|identity| identity.len() == 64)
            .ok_or("application author lacks member identity")?;
        let member = identity[..32].try_into().unwrap();
        let endpoint = identity[32..].try_into().unwrap();
        let ProcessedMessageContent::ApplicationMessage(message) = processed.into_content() else {
            return Err("membership operation on application channel");
        };
        let payload = message.into_bytes();
        if payload.len() > MAX_APPLICATION_PAYLOAD {
            return Err("application payload exceeds bounds");
        }
        Ok(ApplicationMessage {
            member,
            endpoint,
            payload,
        })
    }
}

#[test]
fn application_authentication_replay_and_restart() {
    let admin = Workspace::create([1; 32], "Alex").unwrap();
    let (invite, checkpoint) = admin.issue_invitation().unwrap();
    let pending = PendingJoin::from_invitation(&invite, &checkpoint, [2; 32], "Jordan").unwrap();
    let prepared = admin
        .prepare_admission([2; 32], pending.admission_request().unwrap())
        .unwrap();
    let mut proof = pending.join_proof().unwrap();
    proof
        .apply_add(&prepared.authorization, &prepared.commit)
        .unwrap();
    let mut receiver = pending
        .prepare_workspace(&proof, &prepared.welcome)
        .unwrap();
    let mut sender = prepared.workspace;
    let sender_key = StorageKey::derive(&[11; 32]).unwrap();
    let receiver_key = StorageKey::derive(&[22; 32]).unwrap();
    let id = sender.id();
    let context = b"workspace-scoped topic and publication id";
    let payload = b"arbitrary binary payload\x00\xff";
    let ciphertext = sender.protect_application(context, payload).unwrap();
    assert!(
        !ciphertext
            .windows(payload.len())
            .any(|part| part == payload)
    );
    // Persist/reopen the advanced sender before releasing ciphertext.
    sender =
        Workspace::restore(&sender_key, [1; 32], id, &sender.seal(&sender_key).unwrap()).unwrap();
    let before = receiver.seal(&receiver_key).unwrap();
    let mut wrong_context = Workspace::restore(&receiver_key, [2; 32], id, &before).unwrap();
    assert!(
        wrong_context
            .unprotect_application(b"other topic", &ciphertext)
            .is_err()
    );
    let mut damaged = ciphertext.clone();
    *damaged.last_mut().unwrap() ^= 1;
    let mut tampered = Workspace::restore(&receiver_key, [2; 32], id, &before).unwrap();
    assert!(tampered.unprotect_application(context, &damaged).is_err());
    let mut outsider = Workspace::create([3; 32], "Other workspace").unwrap();
    assert!(
        outsider
            .unprotect_application(context, &ciphertext)
            .is_err()
    );
    let mut trailing = ciphertext.clone();
    trailing.push(0);
    assert!(receiver.unprotect_application(context, &trailing).is_err());
    receiver = Workspace::restore(&receiver_key, [2; 32], id, &before).unwrap();
    assert!(
        receiver
            .unprotect_application(context, &prepared.commit)
            .is_err()
    );
    receiver = Workspace::restore(&receiver_key, [2; 32], id, &before).unwrap();
    let received = receiver
        .unprotect_application(context, &ciphertext)
        .unwrap();
    assert_eq!(received.member, sender.member().unwrap().id());
    assert_eq!(received.endpoint, [1; 32]);
    assert_eq!(received.payload, payload);
    let received_snapshot = receiver.seal(&receiver_key).unwrap();
    receiver = Workspace::restore(&receiver_key, [2; 32], id, &received_snapshot).unwrap();
    assert!(
        receiver
            .unprotect_application(context, &ciphertext)
            .is_err()
    );
    receiver = Workspace::restore(&receiver_key, [2; 32], id, &received_snapshot).unwrap();
    let next = sender
        .protect_application(context, b"next generation")
        .unwrap();
    sender =
        Workspace::restore(&sender_key, [1; 32], id, &sender.seal(&sender_key).unwrap()).unwrap();
    assert_eq!(
        receiver
            .unprotect_application(context, &next)
            .unwrap()
            .payload,
        b"next generation"
    );
    let large_context = vec![7; MAX_APPLICATION_CONTEXT];
    let large_payload = vec![8; MAX_APPLICATION_PAYLOAD];
    let large = sender
        .protect_application(&large_context, &large_payload)
        .unwrap();
    assert!(large.len() <= MAX_APPLICATION_CIPHERTEXT);
    sender =
        Workspace::restore(&sender_key, [1; 32], id, &sender.seal(&sender_key).unwrap()).unwrap();
    assert_eq!(
        receiver
            .unprotect_application(&large_context, &large)
            .unwrap()
            .payload,
        large_payload
    );
    receiver = Workspace::restore(
        &receiver_key,
        [2; 32],
        id,
        &receiver.seal(&receiver_key).unwrap(),
    )
    .unwrap();
    let reverse = receiver
        .protect_application(context, b"reply from member")
        .unwrap();
    let _persisted = receiver.seal(&receiver_key).unwrap();
    let reply = sender.unprotect_application(context, &reverse).unwrap();
    assert_eq!(reply.member, receiver.member().unwrap().id());
    assert_eq!(reply.endpoint, [2; 32]);
    assert_eq!(reply.payload, b"reply from member");
    let _persisted = sender.seal(&sender_key).unwrap();
    assert!(
        receiver
            .unprotect_application(context, &vec![0; MAX_APPLICATION_CIPHERTEXT + 1])
            .is_err()
    );
    assert!(
        sender
            .protect_application(context, &vec![0; MAX_APPLICATION_PAYLOAD + 1])
            .is_err()
    );
}

#[test]
fn selective_subscription_requires_bounded_ratchet_recovery() {
    let admin = Workspace::create([1; 32], "Publisher").unwrap();
    let (invite, checkpoint) = admin.issue_invitation().unwrap();
    let pending =
        PendingJoin::from_invitation(&invite, &checkpoint, [2; 32], "Subscriber").unwrap();
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
    let key = StorageKey::derive(&[22; 32]).unwrap();
    let before = receiver.seal(&key).unwrap();
    // One sender ratchet covers its applications across topics in this MLS group.
    // Keep only the last two packets to exercise the pinned default's exact edge.
    let mut edge = Vec::new();
    let mut beyond = Vec::new();
    for generation in 0..=1001u32 {
        let packet = sender
            .protect_application(b"busy/topic", &generation.to_be_bytes())
            .unwrap();
        if generation == 1000 {
            edge = packet;
        } else if generation == 1001 {
            beyond = packet;
        }
    }
    let mut candidate = Workspace::restore(&key, [2; 32], sender.id(), &before).unwrap();
    assert!(
        candidate
            .unprotect_application(b"busy/topic", &beyond)
            .is_err()
    );
    // Rejected candidates are discarded. An available intermediate ciphertext
    // permits bounded advancement, but the runtime does not retrieve it yet.
    let mut candidate = Workspace::restore(&key, [2; 32], sender.id(), &before).unwrap();
    assert_eq!(
        candidate
            .unprotect_application(b"busy/topic", &edge)
            .unwrap()
            .payload,
        1000u32.to_be_bytes()
    );
    let saved = candidate.seal(&key).unwrap();
    let mut recovered = Workspace::restore(&key, [2; 32], sender.id(), &saved).unwrap();
    assert_eq!(
        recovered
            .unprotect_application(b"busy/topic", &beyond)
            .unwrap()
            .payload,
        1001u32.to_be_bytes()
    );
}

#[test]
fn sparse_empty_control_messages_recover_skipped_topics() {
    // Candidate experiment only: ordinary MLS applications, no new crypto or
    // runtime repair protocol. The receiver never receives busy payload packets.
    let admin = Workspace::create([1; 32], "Publisher").unwrap();
    let (invite, checkpoint) = admin.issue_invitation().unwrap();
    let pending =
        PendingJoin::from_invitation(&invite, &checkpoint, [2; 32], "Subscriber").unwrap();
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
    let sender_key = StorageKey::derive(&[11; 32]).unwrap();
    let receiver_key = StorageKey::derive(&[22; 32]).unwrap();
    let initial = receiver.seal(&receiver_key).unwrap();
    let workspace = sender.id();
    let epoch = sender.epoch();
    let restore =
        |snapshot: &[u8]| Workspace::restore(&receiver_key, [2; 32], workspace, snapshot).unwrap();
    let repair_context = b"candidate/empty-ratchet-control/v1";
    let quiet_context = b"quiet/subscribed-topic";
    let mut controls = Vec::new();
    let mut delayed_quiet = Vec::new();
    let started = std::time::Instant::now();
    for batch in 0..3 {
        for _ in 0..512 {
            let _discarded = sender
                .protect_application(b"busy/unsubscribed-topic", b"not transferred")
                .unwrap();
            // Model the existing durable sender contract before another message.
            let _committed_sender = sender.seal(&sender_key).unwrap();
        }
        if batch == 0 {
            delayed_quiet = sender
                .protect_application(quiet_context, b"older subscribed message")
                .unwrap();
            let _committed_sender = sender.seal(&sender_key).unwrap();
        }
        let control = sender.protect_application(repair_context, b"").unwrap();
        let _committed_sender = sender.seal(&sender_key).unwrap();
        controls.push(control);
    }
    let target = sender
        .protect_application(quiet_context, b"current subscribed message")
        .unwrap();
    let sender_snapshot = sender.seal(&sender_key).unwrap();
    let sender = Workspace::restore(&sender_key, [1; 32], workspace, &sender_snapshot).unwrap();
    assert_eq!(sender.epoch(), epoch); // No membership commit or epoch reset.
    assert!(
        restore(&initial)
            .unprotect_application(quiet_context, &target)
            .is_err()
    );
    assert!(
        restore(&initial)
            .unprotect_application(repair_context, &controls[1])
            .is_err()
    );
    assert!(
        restore(&initial)
            .unprotect_application(b"wrong context", &controls[0])
            .is_err()
    );
    let mut damaged = controls[0].clone();
    *damaged.last_mut().unwrap() ^= 1;
    assert!(
        restore(&initial)
            .unprotect_application(repair_context, &damaged)
            .is_err()
    );
    let mut outsider = Workspace::create([3; 32], "Other workspace").unwrap();
    assert!(
        outsider
            .unprotect_application(repair_context, &controls[0])
            .is_err()
    );

    let receiver_started = std::time::Instant::now();
    let mut recovered = restore(&initial);
    for (index, control) in controls.iter().enumerate() {
        let before = recovered.seal(&receiver_key).unwrap();
        // Apply to a disposable owner; persist/adopt only authenticated state.
        let mut candidate = restore(&before);
        let decoded = candidate
            .unprotect_application(repair_context, control)
            .unwrap();
        assert!(decoded.payload.is_empty());
        assert_eq!(decoded.endpoint, [1; 32]);
        assert_eq!(decoded.member, sender.member().unwrap().id());
        let saved = candidate.seal(&receiver_key).unwrap();
        recovered = restore(&saved);
        assert!(
            restore(&saved)
                .unprotect_application(repair_context, control)
                .is_err()
        );
        if index == 0 {
            // Dropping the middle retained control leaves a gap beyond the limit.
            assert!(
                restore(&saved)
                    .unprotect_application(repair_context, &controls[2])
                    .is_err()
            );
            // An older subscribed message is still recoverable here, before
            // later controls cause its unused key to leave the reorder window.
            assert_eq!(
                restore(&saved)
                    .unprotect_application(quiet_context, &delayed_quiet)
                    .unwrap()
                    .payload,
                b"older subscribed message"
            );
        }
    }
    let advanced = recovered.seal(&receiver_key).unwrap();
    assert!(
        restore(&advanced)
            .unprotect_application(quiet_context, &delayed_quiet)
            .is_err()
    );
    let decoded = recovered
        .unprotect_application(quiet_context, &target)
        .unwrap();
    assert_eq!(decoded.payload, b"current subscribed message");
    assert_eq!(decoded.member, sender.member().unwrap().id());
    assert_eq!(decoded.endpoint, [1; 32]);
    let saved = recovered.seal(&receiver_key).unwrap();
    assert!(
        restore(&saved)
            .unprotect_application(quiet_context, &target)
            .is_err()
    );
    // An explicitly complete, ordered batch can preserve both wanted messages.
    // This is a test oracle, not an authenticated network ordering protocol.
    // No candidate state or plaintext escapes if any later batch element fails.
    let apply_batch = |steps: &[(bool, &[u8], &[u8])]| {
        let mut candidate = restore(&initial);
        let mut wanted = Vec::new();
        for (deliver, context, ciphertext) in steps {
            let message = candidate.unprotect_application(context, ciphertext)?;
            if message.endpoint != [1; 32] || message.member != sender.member().unwrap().id() {
                return Err("batch author mismatch");
            }
            if *deliver {
                wanted.push(message.payload);
            } else if !message.payload.is_empty() {
                return Err("nonempty recovery control");
            }
        }
        Ok((candidate.seal(&receiver_key)?, wanted))
    };
    let ordered: [(bool, &[u8], &[u8]); 5] = [
        (false, repair_context, &controls[0]),
        (true, quiet_context, &delayed_quiet),
        (false, repair_context, &controls[1]),
        (false, repair_context, &controls[2]),
        (true, quiet_context, &target),
    ];
    let request = RecoveryRequest {
        workspace,
        author: sender.member().unwrap().id(),
        epoch,
        selection: [8; 32],
        after: 0,
        through: 1540,
    };
    let response: Vec<_> = ordered
        .iter()
        .map(|(_, context, packet)| (*context, *packet))
        .collect();
    let signed_offer = sender.sign_recovery_offer(&request, &response).unwrap();
    let verifier = restore(&initial);
    let offer = verifier
        .verify_recovery_offer(&request, &signed_offer)
        .unwrap();
    offer.verify_packets(&response).unwrap();
    let mut omitted_response = response.clone();
    omitted_response.remove(1);
    assert!(offer.verify_packets(&omitted_response).is_err());
    let (batch_snapshot, wanted) = apply_batch(&ordered).unwrap();
    assert_eq!(
        wanted,
        [
            b"older subscribed message".to_vec(),
            b"current subscribed message".to_vec()
        ]
    );
    let adopted = restore(&batch_snapshot);
    let adopted_snapshot = adopted.seal(&receiver_key).unwrap();
    for packet in [&delayed_quiet, &target] {
        assert!(
            restore(&adopted_snapshot)
                .unprotect_application(quiet_context, packet)
                .is_err()
        );
    }
    // Authentication of supplied packets does not prove response completeness:
    // removing an entire wanted packet can still produce an apparently valid batch.
    let omitted = apply_batch(&[ordered[0], ordered[2], ordered[3], ordered[4]]).unwrap();
    assert_eq!(omitted.1, [b"current subscribed message".to_vec()]);
    assert!(
        restore(&omitted.0)
            .unprotect_application(quiet_context, &delayed_quiet)
            .is_err()
    );
    let mut reversed = ordered;
    reversed.reverse();
    assert!(apply_batch(&reversed).is_err());
    assert!(apply_batch(&[ordered[0], ordered[1], ordered[3], ordered[4]]).is_err());
    let mut duplicate = ordered.to_vec();
    duplicate.insert(2, ordered[1]);
    assert!(apply_batch(&duplicate).is_err());
    let mut corrupt_tail = target.clone();
    *corrupt_tail.last_mut().unwrap() ^= 1;
    let mut corrupt = ordered;
    corrupt[4].2 = &corrupt_tail;
    assert!(apply_batch(&corrupt).is_err());
    // Failed candidate attempts leave the last committed owner usable. There is
    // no rollback of a live adopted state and no partial application callback.
    assert_eq!(apply_batch(&ordered).unwrap().1, wanted);
    println!(
        "ordered_control_probe wanted_messages=2 steps=5 reversed_rejected=true missing_middle_rejected=true duplicate_rejected=true corrupt_tail_rejected=true batch_atomicity=memory_only complete_order=fixture_oracle omitted_wanted_undetectable_without_coverage=true signed_offer_rejects_holder_omission=true"
    );
    println!(
        "sparse_control_probe busy_packets_omitted=1536 controls={} control_bytes={} target_bytes={} elapsed_ms={} recovery_ms={} epoch_unchanged=true delayed_quiet_lost_if_controls_advanced_first=true",
        controls.len(),
        controls.iter().map(Vec::len).sum::<usize>(),
        target.len(),
        started.elapsed().as_millis(),
        receiver_started.elapsed().as_millis()
    );
}
