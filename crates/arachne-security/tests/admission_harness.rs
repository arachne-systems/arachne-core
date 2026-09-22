//! App-independent admission capacity harness.
//!
//! This deliberately crosses only the lower security-owner seam. It does not
//! claim transport, Android, ATAK, SQLite, or UI capacity.

use arachne_security::{
    AdmissionAssessment, AdmissionAttempt, AdmissionEnqueue, AdmissionQueue, MAX_ADMISSION_BATCH,
    PendingJoin, Workspace,
};
use std::time::Instant;

fn endpoint(index: usize) -> [u8; 32] {
    let mut value = [0; 32];
    value[..8].copy_from_slice(&(index as u64 + 1).to_be_bytes());
    value[8..16].copy_from_slice(&(!(index as u64)).to_be_bytes());
    value
}

fn run(member_count: usize) {
    assert!(member_count >= 32);
    let started = Instant::now();
    let mut owner = Workspace::create([200; 32], "Admission harness owner").unwrap();
    let (invitation, checkpoint) = owner.issue_invitation().unwrap();
    let mut queue = AdmissionQueue::new();

    let mut request_build_time = std::time::Duration::ZERO;
    for index in 0..member_count {
        let request_started = Instant::now();
        let remote_endpoint = endpoint(index);
        let pending =
            PendingJoin::from_invitation(&invitation, &checkpoint, remote_endpoint, "Burst member")
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
            owner = Workspace::restore_records([200; 32], owner.id(), &records).unwrap();
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
    owner = Workspace::restore_records([200; 32], owner.id(), &records).unwrap();
    restore_time += restore_started.elapsed();
    assert_eq!(owner.member_count(), member_count + 1);

    // A founding-epoch invitation must still produce verifiable history after
    // the burst and all simulated owner restarts.
    let late_endpoint = endpoint(member_count + 1);
    let late = PendingJoin::from_invitation(&invitation, &checkpoint, late_endpoint, "Late member")
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
    let mut owner = Workspace::create([201; 32], "Batch harness owner").unwrap();
    let (invitation, checkpoint) = owner.issue_invitation().unwrap();
    let mut pending = Vec::with_capacity(member_count);
    let mut requests = Vec::with_capacity(member_count);
    let mut validated = Vec::with_capacity(member_count);
    let request_started = Instant::now();
    for index in 0..member_count {
        let endpoint = endpoint(index + 10_000);
        let join =
            PendingJoin::from_invitation(&invitation, &checkpoint, endpoint, "Batched member")
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
    owner = Workspace::restore_records([201; 32], owner.id(), &records).unwrap();
    assert_eq!(owner.member_count(), member_count + 1);
    let late = PendingJoin::from_invitation(
        &invitation,
        &checkpoint,
        endpoint(member_count + 20_000),
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
    let mut owner = Workspace::create([203; 32], "Large workspace owner").unwrap();
    let (invitation, checkpoint) = owner.issue_invitation().unwrap();
    let joiner = |index: usize| {
        PendingJoin::from_invitation(&invitation, &checkpoint, endpoint(index + 30_000), "Member").unwrap()
    };
    // The early member: admitted alone in the first batch, then only follows.
    let early = joiner(0);
    let request = early.admission_request().unwrap().to_vec();
    let AdmissionAssessment::Ready(validated) = owner.assess_admission(endpoint(30_000), &request).unwrap() else {
        panic!("open invitation needs no approval");
    };
    let prepared = owner.prepare_validated_admission_batch(&[(endpoint(30_000), request.as_slice(), &validated)]).unwrap();
    let mut proof = early.join_proof().unwrap();
    let authorization = arachne_security::MembershipAuthorization::Admission(prepared.replies[0].authorization.clone());
    proof.apply_transition(&authorization, &prepared.commit).unwrap();
    let mut member = early.prepare_workspace(&proof, &prepared.welcome).unwrap();
    owner = prepared.workspace;
    let mut next = 1;
    while owner.member_count() < 310 {
        let range = next..(next + MAX_ADMISSION_BATCH);
        let joins: Vec<_> = range.clone().map(joiner).collect();
        let requests: Vec<_> = joins.iter().map(|join| join.admission_request().unwrap().to_vec()).collect();
        let validated: Vec<_> = range.clone().zip(&requests).map(|(index, request)| {
            match owner.assess_admission(endpoint(index + 30_000), request).unwrap() {
                AdmissionAssessment::Ready(validated) => validated,
                _ => panic!("open invitation needs no approval"),
            }
        }).collect();
        let entries: Vec<_> = range.clone().zip(requests.iter().zip(&validated))
            .map(|(index, (request, validated))| (endpoint(index + 30_000), request.as_slice(), validated)).collect();
        let prepared = owner.prepare_validated_admission_batch(&entries).unwrap();
        let authorizations: Vec<_> = prepared.replies.iter().map(|reply| reply.authorization.clone()).collect();
        member = member.prepare_admission_batch_update(&authorizations, &prepared.commit).unwrap_or_else(|error| {
            panic!("member at {} members could not follow the next batch: {error}", member.member_count())
        });
        owner = prepared.workspace;
        next = range.end;
    }
    assert_eq!(member.member_count(), owner.member_count());
}

/// Known limit: a new invitation's checkpoint is signed GroupInfo with the
/// ratchet tree and crosses the network, so it keeps the 64 KiB wire bound.
/// Past ~250 members an administrator cannot issue a new invitation. An
/// invitation issued earlier keeps working for any number of joiners. Needs a
/// checkpoint that does not carry the whole tree (byte-bound finding F3).
#[test]
#[ignore = "known limit: invitation checkpoint exceeds 64 KiB past ~250 members (F3)"]
fn an_administrator_invites_past_three_hundred_members() {
    let mut owner = Workspace::create([204; 32], "Large workspace owner").unwrap();
    let (invitation, checkpoint) = owner.issue_invitation().unwrap();
    let mut next = 0;
    while owner.member_count() < 310 {
        let range = next..(next + MAX_ADMISSION_BATCH);
        let joins: Vec<_> = range.clone()
            .map(|index| PendingJoin::from_invitation(&invitation, &checkpoint, endpoint(index + 40_000), "Member").unwrap())
            .collect();
        let requests: Vec<_> = joins.iter().map(|join| join.admission_request().unwrap().to_vec()).collect();
        let validated: Vec<_> = range.clone().zip(&requests).map(|(index, request)| {
            match owner.assess_admission(endpoint(index + 40_000), request).unwrap() {
                AdmissionAssessment::Ready(validated) => validated,
                _ => panic!("open invitation needs no approval"),
            }
        }).collect();
        let entries: Vec<_> = range.clone().zip(requests.iter().zip(&validated))
            .map(|(index, (request, validated))| (endpoint(index + 40_000), request.as_slice(), validated)).collect();
        owner = owner.prepare_validated_admission_batch(&entries).unwrap().workspace;
        next = range.end;
    }
    let (late_invitation, late_checkpoint) = owner.issue_invitation().unwrap();
    let late = PendingJoin::from_invitation(&late_invitation, &late_checkpoint, endpoint(39_999), "Late member").unwrap();
    let request = late.admission_request().unwrap().to_vec();
    let AdmissionAssessment::Ready(validated) = owner.assess_admission(endpoint(39_999), &request).unwrap() else {
        panic!("open invitation needs no approval");
    };
    let prepared = owner.prepare_validated_admission_batch(&[(endpoint(39_999), request.as_slice(), &validated)]).unwrap();
    let mut proof = late.join_proof().unwrap();
    for (authorization, commit) in prepared.workspace.membership_history(endpoint(39_999), &request, &late_checkpoint).unwrap() {
        proof.apply_transition(&authorization, &commit).unwrap();
    }
    let joined = late.prepare_workspace(&proof, &prepared.welcome).unwrap();
    assert_eq!(joined.member_count(), owner.member_count() + 1);
}
