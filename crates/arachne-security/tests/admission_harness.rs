//! App-independent admission capacity harness.
//!
//! This deliberately crosses only the lower security-owner seam. It does not
//! claim transport, Android, ATAK, SQLite, or UI capacity.

mod common;
use arachne_security::{
    AdmissionAssessment, AdmissionAttempt, AdmissionEnqueue, AdmissionQueue, MAX_ADMISSION_BATCH,
    PendingJoin, Workspace,
};
use common::{test_endpoint, test_key, test_key_for};
use std::time::Instant;

fn endpoint(index: usize) -> [u8; 32] {
    test_endpoint(1_000_000 + index as u64)
}

fn run(member_count: usize) {
    assert!(member_count >= 32);
    let started = Instant::now();
    let mut owner = Workspace::create(test_key(200), "Admission harness owner").unwrap();
    let (registration, invitation, checkpoint) = owner.prepare_invitation(0, false, false).unwrap();
    owner = registration.workspace;
    let mut queue = AdmissionQueue::new();

    let mut request_build_time = std::time::Duration::ZERO;
    for index in 0..member_count {
        let request_started = Instant::now();
        let remote_endpoint = endpoint(index);
        let pending = PendingJoin::from_invitation(
            &invitation,
            &checkpoint,
            test_key_for(remote_endpoint),
            "Burst member",
        )
        .unwrap();
        let attempt = AdmissionAttempt::new(
            remote_endpoint,
            pending.admission_request().unwrap().to_vec(),
        )
        .unwrap();
        assert_eq!(queue.enqueue(attempt), Ok(AdmissionEnqueue::Added));
        request_build_time += request_started.elapsed();
    }

    let mut accepted = 0;
    let mut exact_retries = 0;
    let mut restarts = 0;
    let mut prepare_time = std::time::Duration::ZERO;
    let mut retry_time = std::time::Duration::ZERO;
    let mut restore_time = std::time::Duration::ZERO;
    while let Some(attempt) = queue.pop() {
        // A lost response is represented by the same durable attempt being
        // re-enqueued. It must retrieve the retained result, never create Add #2.
        let lookup_started = Instant::now();
        if owner
            .retained_admission(attempt.endpoint(), attempt.request())
            .unwrap()
            .is_some()
        {
            retry_time += lookup_started.elapsed();
            exact_retries += 1;
            continue;
        }

        let prepare_started = Instant::now();
        owner = owner
            .prepare_admission(attempt.endpoint(), attempt.request())
            .unwrap()
            .workspace;
        prepare_time += prepare_started.elapsed();
        accepted += 1;

        // Restore the lower library from its authenticated record boundary.
        // This models a process restart without pulling persistence or Android
        // into the domain test.
        if [16, 64, 128, 256].contains(&accepted) && accepted < member_count {
            let restore_started = Instant::now();
            let records = owner.export_records().unwrap();
            owner = Workspace::restore_records(test_endpoint(200), owner.id(), &records).unwrap();
            restore_time += restore_started.elapsed();
            restarts += 1;
        }
        if accepted % 8 == 0 {
            assert_eq!(
                queue.enqueue(attempt),
                Ok(AdmissionEnqueue::Added),
                "a completed attempt must be retryable after its queue slot is released"
            );
        }
    }

    assert_eq!(accepted, member_count);
    assert!(exact_retries >= member_count / 8);
    assert_eq!(owner.member_count(), member_count + 1);

    let restore_started = Instant::now();
    let records = owner.export_records().unwrap();
    owner = Workspace::restore_records(test_endpoint(200), owner.id(), &records).unwrap();
    restore_time += restore_started.elapsed();
    assert_eq!(owner.member_count(), member_count + 1);

    // A founding-epoch invitation must still produce verifiable history after
    // the burst and all simulated owner restarts.
    let late_endpoint = endpoint(member_count + 1);
    let late = PendingJoin::from_invitation(
        &invitation,
        &checkpoint,
        test_key_for(late_endpoint),
        "Late member",
    )
    .unwrap();
    let history = owner
        .membership_history(
            late_endpoint,
            late.admission_request().unwrap(),
            &checkpoint,
        )
        .unwrap();
    assert_eq!(history.len(), member_count);

    println!(
        "admission_harness members={} accepted={} exact_retries={} restarts={} elapsed_ms={} request_build_ms={} prepare_ms={} retry_ms={} restore_ms={}",
        member_count,
        accepted,
        exact_retries,
        restarts,
        started.elapsed().as_millis(),
        request_build_time.as_millis(),
        prepare_time.as_millis(),
        retry_time.as_millis(),
        restore_time.as_millis()
    );
}

fn run_batched(member_count: usize) {
    assert!(member_count >= 2);
    let started = Instant::now();
    let mut owner = Workspace::create(test_key(201), "Batch harness owner").unwrap();
    let (registration, invitation, checkpoint) = owner.prepare_invitation(0, false, false).unwrap();
    owner = registration.workspace;
    let mut pending = Vec::with_capacity(member_count);
    let mut requests = Vec::with_capacity(member_count);
    let mut validated = Vec::with_capacity(member_count);
    let request_started = Instant::now();
    for index in 0..member_count {
        let endpoint = endpoint(index + 10_000);
        let join = PendingJoin::from_invitation(
            &invitation,
            &checkpoint,
            test_key_for(endpoint),
            "Batched member",
        )
        .unwrap();
        let request = join.admission_request().unwrap().to_vec();
        let assessment = owner.assess_admission(endpoint, &request).unwrap();
        let request_validation = match assessment {
            AdmissionAssessment::Ready(request) => request,
            _ => panic!("batch invitation unexpectedly needs approval"),
        };
        pending.push(join);
        requests.push(request);
        validated.push(request_validation);
    }
    let request_build_ms = request_started.elapsed().as_millis();
    let mut prepare_ms = 0;
    let mut batches = 0;
    let mut joined = 0;
    let validate_all = std::env::var_os("ARACHNE_VALIDATE_ALL_JOINERS").is_some();
    let batch_size = std::env::var("ARACHNE_ADMISSION_BATCH_SIZE")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(MAX_ADMISSION_BATCH);
    assert!((1..=MAX_ADMISSION_BATCH).contains(&batch_size));
    for start in (0..member_count).step_by(batch_size) {
        let end = (start + batch_size).min(member_count);
        let entries: Vec<_> = (start..end)
            .map(|index| {
                (
                    endpoint(index + 10_000),
                    requests[index].as_slice(),
                    &validated[index],
                )
            })
            .collect();
        let prepared_started = Instant::now();
        let prepared = owner.prepare_validated_admission_batch(&entries).unwrap();
        prepare_ms += prepared_started.elapsed().as_millis();
        assert_eq!(prepared.replies.len(), end - start);
        println!(
            "admission_batch start={} count={} commit_bytes={} welcome_bytes={}",
            start,
            end - start,
            prepared.commit.len(),
            prepared.welcome.len()
        );
        let authorization = arachne_security::MembershipAuthorization::AdmissionBatch(
            prepared
                .replies
                .iter()
                .map(|reply| reply.authorization.clone())
                .collect(),
        );
        for (index, join) in pending[start..end].iter().enumerate() {
            let boundary_sample =
                (start == 0 && index == 0) || (end == member_count && index + 1 == end - start);
            if !validate_all && !boundary_sample {
                continue;
            }
            let mut proof = join.join_proof().unwrap();
            for (authorization, commit) in owner
                .membership_history(
                    endpoint(start + index + 10_000),
                    join.admission_request().unwrap(),
                    &checkpoint,
                )
                .unwrap()
            {
                proof.apply_transition(&authorization, &commit).unwrap();
            }
            proof
                .apply_transition(&authorization, &prepared.commit)
                .unwrap_or_else(|error| {
                    panic!(
                        "batch_start={} commit_bytes={} proof_history_bytes={} error={error}",
                        start,
                        prepared.commit.len(),
                        proof.history().len()
                    )
                });
            let joined_workspace = join.prepare_workspace(&proof, &prepared.welcome).unwrap();
            assert_eq!(joined_workspace.member_count(), end + 1);
            joined += 1;
        }
        owner = prepared.workspace;
        batches += 1;
    }
    let expected_joiners = if validate_all { member_count } else { 2 };
    assert_eq!(joined, expected_joiners);
    assert_eq!(owner.member_count(), member_count + 1);
    for (index, request) in requests.iter().enumerate().take(member_count) {
        assert!(
            owner
                .retained_admission(endpoint(index + 10_000), request)
                .unwrap()
                .is_some()
        );
    }
    let records = owner.export_records().unwrap();
    owner = Workspace::restore_records(test_endpoint(201), owner.id(), &records).unwrap();
    assert_eq!(owner.member_count(), member_count + 1);
    let late = PendingJoin::from_invitation(
        &invitation,
        &checkpoint,
        test_key_for(endpoint(member_count + 20_000)),
        "Late batched member",
    )
    .unwrap();
    let history = owner
        .membership_history(
            endpoint(member_count + 20_000),
            late.admission_request().unwrap(),
            &checkpoint,
        )
        .unwrap();
    assert_eq!(history.len(), batches);
    println!(
        "admission_batch_harness members={} batches={} joined_checked={} elapsed_ms={} request_build_ms={} prepare_ms={}",
        member_count,
        batches,
        joined,
        started.elapsed().as_millis(),
        request_build_ms,
        prepare_ms
    );
}

#[test]
fn admission_harness_covers_burst_retry_and_restart() {
    run(32);
}

#[test]
#[ignore = "explicit native scale run"]
fn admission_harness_scales_to_hundreds() {
    run(std::env::var("ARACHNE_ADMISSION_MEMBERS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(256));
}

#[test]
#[ignore = "explicit native batch scale run"]
fn admission_batch_harness_scales_to_thousands() {
    run_batched(
        std::env::var("ARACHNE_ADMISSION_BATCH_MEMBERS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(256),
    );
}

#[test]
fn admission_batch_harness_covers_shared_welcome_and_restart() {
    run_batched(2);
}

/// An existing member must keep applying batch Adds past the size where its
/// own group state (GroupInfo with the ratchet tree) exceeds the 64 KiB wire
/// bound for received checkpoints. On tablets every member stopped at 250 of
/// 555 members with "checkpoint exceeds bounds" (2026-09-18): the member's
/// verifier re-read its own local state through the untrusted-input bound.
#[test]
fn an_existing_member_follows_batch_adds_past_three_hundred_members() {
    let mut owner = Workspace::create(test_key(203), "Large workspace owner").unwrap();
    let (registration, invitation, checkpoint) = owner.prepare_invitation(0, false, false).unwrap();
    owner = registration.workspace;
    let joiner = |index: usize| {
        PendingJoin::from_invitation(
            &invitation,
            &checkpoint,
            test_key_for(endpoint(index + 30_000)),
            "Member",
        )
        .unwrap()
    };
    // The early member: admitted alone in the first batch, then only follows.
    let early = joiner(0);
    let request = early.admission_request().unwrap().to_vec();
    let AdmissionAssessment::Ready(validated) =
        owner.assess_admission(endpoint(30_000), &request).unwrap()
    else {
        panic!("open invitation needs no approval");
    };
    let prepared = owner
        .prepare_validated_admission_batch(&[(endpoint(30_000), request.as_slice(), &validated)])
        .unwrap();
    let mut proof = early.join_proof().unwrap();
    let authorization = arachne_security::MembershipAuthorization::Admission(
        prepared.replies[0].authorization.clone(),
    );
    proof
        .apply_transition(&authorization, &prepared.commit)
        .unwrap();
    let mut member = early.prepare_workspace(&proof, &prepared.welcome).unwrap();
    owner = prepared.workspace;
    let mut next = 1;
    while owner.member_count() < 310 {
        let range = next..(next + MAX_ADMISSION_BATCH);
        let joins: Vec<_> = range.clone().map(joiner).collect();
        let requests: Vec<_> = joins
            .iter()
            .map(|join| join.admission_request().unwrap().to_vec())
            .collect();
        let validated: Vec<_> = range
            .clone()
            .zip(&requests)
            .map(|(index, request)| {
                match owner
                    .assess_admission(endpoint(index + 30_000), request)
                    .unwrap()
                {
                    AdmissionAssessment::Ready(validated) => validated,
                    _ => panic!("open invitation needs no approval"),
                }
            })
            .collect();
        let entries: Vec<_> = range
            .clone()
            .zip(requests.iter().zip(&validated))
            .map(|(index, (request, validated))| {
                (endpoint(index + 30_000), request.as_slice(), validated)
            })
            .collect();
        let prepared = owner.prepare_validated_admission_batch(&entries).unwrap();
        let authorizations: Vec<_> = prepared
            .replies
            .iter()
            .map(|reply| reply.authorization.clone())
            .collect();
        member = member
            .prepare_admission_batch_update(&authorizations, &prepared.commit)
            .unwrap_or_else(|error| {
                panic!(
                    "member at {} members could not follow the next batch: {error}",
                    member.member_count()
                )
            });
        owner = prepared.workspace;
        next = range.end;
    }
    assert_eq!(member.member_count(), owner.member_count());
}

/// Past ~250 members an administrator prepared a management commit (its own
/// state uses the local bound), but every other member re-read its own state
/// through the 64 KiB wire bound in `verify_management` and rejected the
/// commit. The administrator advanced and the members did not: a fork (B3).
#[test]
fn an_existing_member_accepts_management_past_three_hundred_members() {
    let owner = Workspace::create(test_key(205), "Large workspace owner").unwrap();
    let (registered, invitation, checkpoint) = owner.prepare_invitation(0, false, false).unwrap();
    let mut owner = registered.workspace;
    let joiner = |index: usize| {
        PendingJoin::from_invitation(
            &invitation,
            &checkpoint,
            test_key_for(endpoint(index + 50_000)),
            "Member",
        )
        .unwrap()
    };
    let early = joiner(0);
    let request = early.admission_request().unwrap().to_vec();
    let AdmissionAssessment::Ready(validated) =
        owner.assess_admission(endpoint(50_000), &request).unwrap()
    else {
        panic!("open invitation needs no approval");
    };
    let prepared = owner
        .prepare_validated_admission_batch(&[(endpoint(50_000), request.as_slice(), &validated)])
        .unwrap();
    let mut proof = early.join_proof().unwrap();
    let authorization = arachne_security::MembershipAuthorization::Admission(
        prepared.replies[0].authorization.clone(),
    );
    proof
        .apply_transition(&authorization, &prepared.commit)
        .unwrap();
    let mut member = early.prepare_workspace(&proof, &prepared.welcome).unwrap();
    owner = prepared.workspace;
    let mut next = 1;
    while owner.member_count() < 310 {
        let range = next..(next + MAX_ADMISSION_BATCH);
        let joins: Vec<_> = range.clone().map(joiner).collect();
        let requests: Vec<_> = joins
            .iter()
            .map(|join| join.admission_request().unwrap().to_vec())
            .collect();
        let validated: Vec<_> = range
            .clone()
            .zip(&requests)
            .map(|(index, request)| {
                match owner
                    .assess_admission(endpoint(index + 50_000), request)
                    .unwrap()
                {
                    AdmissionAssessment::Ready(validated) => validated,
                    _ => panic!("open invitation needs no approval"),
                }
            })
            .collect();
        let entries: Vec<_> = range
            .clone()
            .zip(requests.iter().zip(&validated))
            .map(|(index, (request, validated))| {
                (endpoint(index + 50_000), request.as_slice(), validated)
            })
            .collect();
        let prepared = owner.prepare_validated_admission_batch(&entries).unwrap();
        let authorizations: Vec<_> = prepared
            .replies
            .iter()
            .map(|reply| reply.authorization.clone())
            .collect();
        member = member
            .prepare_admission_batch_update(&authorizations, &prepared.commit)
            .unwrap();
        owner = prepared.workspace;
        next = range.end;
    }
    let own_id = member.member().unwrap().id();
    let target = owner
        .member_roster()
        .unwrap()
        .into_iter()
        .find(|m| !m.administrator && m.id != own_id)
        .unwrap()
        .id;
    let action = arachne_security::ManagementAction::Remove(target);
    let prepared = owner.prepare_management(action).unwrap();
    member
        .verify_step(&prepared.authorization, &prepared.commit)
        .unwrap_or_else(|error| {
            panic!(
                "member at {} members rejected the management commit: {error}",
                member.member_count()
            )
        });
    let arachne_security::PreparedManagementUpdate::Active(member) = member
        .prepare_step_update(&prepared.authorization, &prepared.commit)
        .unwrap()
    else {
        panic!("removal of another member removed this member")
    };
    assert_eq!(member.epoch(), prepared.workspace.epoch());
    assert_eq!(member.member_count(), prepared.workspace.member_count());
    // The runtime saves the accepted state before it adopts it.
    let records = member.export_records().unwrap();
    let restored = Workspace::restore_records(endpoint(50_000), member.id(), &records).unwrap();
    assert_eq!(restored.epoch(), prepared.workspace.epoch());
}

/// B3a: a new invitation's checkpoint once was signed GroupInfo with the
/// ratchet tree inside one 64 KiB wire bound, so past ~241 members an
/// administrator could not issue an invitation a joiner would accept.
#[test]
fn an_administrator_invites_past_three_hundred_members() {
    let mut owner = Workspace::create(test_key(204), "Large workspace owner").unwrap();
    let (registration, invitation, checkpoint) = owner.prepare_invitation(0, false, false).unwrap();
    owner = registration.workspace;
    let mut next = 0;
    while owner.member_count() < 310 {
        let range = next..(next + MAX_ADMISSION_BATCH);
        let joins: Vec<_> = range
            .clone()
            .map(|index| {
                PendingJoin::from_invitation(
                    &invitation,
                    &checkpoint,
                    test_key_for(endpoint(index + 40_000)),
                    "Member",
                )
                .unwrap()
            })
            .collect();
        let requests: Vec<_> = joins
            .iter()
            .map(|join| join.admission_request().unwrap().to_vec())
            .collect();
        let validated: Vec<_> = range
            .clone()
            .zip(&requests)
            .map(|(index, request)| {
                match owner
                    .assess_admission(endpoint(index + 40_000), request)
                    .unwrap()
                {
                    AdmissionAssessment::Ready(validated) => validated,
                    _ => panic!("open invitation needs no approval"),
                }
            })
            .collect();
        let entries: Vec<_> = range
            .clone()
            .zip(requests.iter().zip(&validated))
            .map(|(index, (request, validated))| {
                (endpoint(index + 40_000), request.as_slice(), validated)
            })
            .collect();
        owner = owner
            .prepare_validated_admission_batch(&entries)
            .unwrap()
            .workspace;
        next = range.end;
    }
    let (registration, late_invitation, late_checkpoint) =
        owner.prepare_invitation(0, false, false).unwrap();
    owner = registration.workspace;
    let late = PendingJoin::from_invitation(
        &late_invitation,
        &late_checkpoint,
        test_key_for(endpoint(39_999)),
        "Late member",
    )
    .unwrap();
    let request = late.admission_request().unwrap().to_vec();
    let AdmissionAssessment::Ready(validated) =
        owner.assess_admission(endpoint(39_999), &request).unwrap()
    else {
        panic!("open invitation needs no approval");
    };
    let prepared = owner
        .prepare_validated_admission_batch(&[(endpoint(39_999), request.as_slice(), &validated)])
        .unwrap();
    let mut proof = late.join_proof().unwrap();
    for (authorization, commit) in prepared
        .workspace
        .membership_history(endpoint(39_999), &request, &late_checkpoint)
        .unwrap()
    {
        proof.apply_transition(&authorization, &commit).unwrap();
    }
    let joined = late.prepare_workspace(&proof, &prepared.welcome).unwrap();
    assert_eq!(joined.member_count(), owner.member_count() + 1);
}

/// Grow an owner to at least `size` members from one early invitation.
fn grow(seed: u8, size: usize, base: usize) -> Workspace {
    let owner = Workspace::create(test_key(u64::from(seed)), "Large workspace owner").unwrap();
    let (registration, invitation, checkpoint) = owner.prepare_invitation(0, false, false).unwrap();
    let mut owner = registration.workspace;
    let mut next = 0;
    while owner.member_count() < size {
        let range = next..(next + MAX_ADMISSION_BATCH);
        let joins: Vec<_> = range
            .clone()
            .map(|index| {
                PendingJoin::from_invitation(
                    &invitation,
                    &checkpoint,
                    test_key_for(endpoint(index + base)),
                    "Member",
                )
                .unwrap()
            })
            .collect();
        let requests: Vec<_> = joins
            .iter()
            .map(|join| join.admission_request().unwrap().to_vec())
            .collect();
        let validated: Vec<_> = range
            .clone()
            .zip(&requests)
            .map(|(index, request)| {
                match owner
                    .assess_admission(endpoint(index + base), request)
                    .unwrap()
                {
                    AdmissionAssessment::Ready(validated) => validated,
                    _ => panic!("open invitation needs no approval"),
                }
            })
            .collect();
        let entries: Vec<_> = range
            .clone()
            .zip(requests.iter().zip(&validated))
            .map(|(index, (request, validated))| {
                (endpoint(index + base), request.as_slice(), validated)
            })
            .collect();
        owner = owner
            .prepare_validated_admission_batch(&entries)
            .unwrap()
            .workspace;
        next = range.end;
    }
    owner
}

/// B3a end to end in the security crate: a registered invitation issued past
/// 300 members is retained, survives an owner restore, resolves from the
/// request alone after the owner moves on, and its joiner survives a pending
/// restore and joins. Prints the measured checkpoint sizes.
fn registered_invitation_admits_at(size: usize, seed: u8, base: usize) {
    let owner = grow(seed, size, base);
    let members = owner.member_count();
    let (prepared, invitation, checkpoint) = owner.prepare_invitation(0, false, false).unwrap();
    let mut owner = prepared.workspace;
    // The invitation pins the checkpoint's pin, and the pin alone.
    assert_eq!(
        arachne_security::checkpoint_digest(&checkpoint).unwrap(),
        invitation.checkpoint_digest()
    );
    let pin = u32::from_be_bytes(checkpoint[5..9].try_into().unwrap()) as usize;
    let tree = checkpoint.len() - 13 - pin;
    println!(
        "B3a checkpoint at {members} members: pin {pin} B, tree {tree} B ({} B/member), total {} B",
        tree / members,
        checkpoint.len()
    );
    assert!(
        pin <= arachne_security::MAX_CHECKPOINT_PIN
            && tree <= arachne_security::MAX_CHECKPOINT_TREE
    );

    // The joiner's pending state, with the checkpoint, survives a restart.
    let key = arachne_security::StorageKey::derive(&[seed; 32]).unwrap();
    let late = PendingJoin::from_invitation(
        &invitation,
        &checkpoint,
        test_key_for(endpoint(base - 1)),
        "Late member",
    )
    .unwrap();
    let sealed = late.seal(&key).unwrap();
    assert!(sealed.len() <= arachne_security::MAX_SEALED_PENDING_JOIN);
    let late = PendingJoin::restore(&key, endpoint(base - 1), owner.id(), &sealed).unwrap();
    assert_eq!(late.admission_checkpoint().unwrap(), checkpoint.as_slice());

    // The owner moves on (one more member), then restores from its records:
    // the request alone must still resolve the retained, pinned checkpoint.
    let filler = grow_one(&mut owner, &invitation, &checkpoint, base - 2);
    assert_eq!(owner.member_count(), filler);
    assert_ne!(owner.join_checkpoint().unwrap(), checkpoint);
    let records = owner.export_records().unwrap();
    let owner = Workspace::restore_records(owner.endpoint(), owner.id(), &records).unwrap();
    let request = late.admission_request().unwrap().to_vec();
    assert_eq!(owner.admission_checkpoint(&request).unwrap(), checkpoint);

    let AdmissionAssessment::Ready(validated) = owner
        .assess_admission(endpoint(base - 1), &request)
        .unwrap()
    else {
        panic!("open invitation needs no approval");
    };
    owner
        .check_membership_history(endpoint(base - 1), &request, &checkpoint)
        .unwrap();
    let prepared = owner
        .prepare_validated_admission_batch(&[(endpoint(base - 1), request.as_slice(), &validated)])
        .unwrap();
    let mut proof = late.join_proof().unwrap();
    for (authorization, commit) in prepared
        .workspace
        .membership_history(endpoint(base - 1), &request, &checkpoint)
        .unwrap()
    {
        proof.apply_transition(&authorization, &commit).unwrap();
    }
    let joined = late.prepare_workspace(&proof, &prepared.welcome).unwrap();
    assert_eq!(joined.member_count(), owner.member_count() + 1);
    assert_eq!(joined.epoch(), prepared.workspace.epoch());
}

/// Admit one member through `invitation`; returns the new member count.
fn grow_one(
    owner: &mut Workspace,
    invitation: &arachne_security::Invitation,
    checkpoint: &[u8],
    index: usize,
) -> usize {
    let join = PendingJoin::from_invitation(
        invitation,
        checkpoint,
        test_key_for(endpoint(index)),
        "Filler",
    )
    .unwrap();
    let request = join.admission_request().unwrap().to_vec();
    let AdmissionAssessment::Ready(validated) =
        owner.assess_admission(endpoint(index), &request).unwrap()
    else {
        panic!("open invitation needs no approval");
    };
    let prepared = owner
        .prepare_validated_admission_batch(&[(endpoint(index), request.as_slice(), &validated)])
        .unwrap();
    *owner = prepared.workspace;
    owner.member_count()
}

#[test]
fn a_registered_invitation_admits_past_three_hundred_members() {
    registered_invitation_admits_at(310, 207, 60_000);
}

/// Measures the 1,000-member target. The checkpoint side holds: the joiner
/// accepts a 1,025-member checkpoint. Registering a new invitation needs a
/// management commit, which has its own 64 KiB commit bound; this prints that
/// commit's size per roster size so the separate limit is visible.
#[test]
#[ignore = "explicit 1,000-member invitation checkpoint measurement"]
fn an_administrator_checkpoint_past_one_thousand_members() {
    let mut size = 129;
    while size <= 1_025 {
        let owner = grow(208, size, 70_000);
        let checkpoint = owner.join_checkpoint().unwrap();
        let pin = u32::from_be_bytes(checkpoint[5..9].try_into().unwrap()) as usize;
        arachne_security::JoinProof::from_trusted_checkpoint(
            owner.id(),
            arachne_security::checkpoint_digest(&checkpoint).unwrap(),
            &checkpoint,
        )
        .unwrap();
        let registration = owner.prepare_invitation(0, false, false);
        println!(
            "B3a {} members: checkpoint pin {pin} B, tree {} B, total {} B; registration commit {}",
            owner.member_count(),
            checkpoint.len() - 13 - pin,
            checkpoint.len(),
            match &registration {
                Ok((prepared, ..)) => format!("{} B", prepared.commit.len()),
                Err(error) => format!("failed: {error}"),
            }
        );
        size += 128;
    }
}
