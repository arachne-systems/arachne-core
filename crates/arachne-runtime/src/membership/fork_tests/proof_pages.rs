//! Real MLS proofs through the native fragment consumers and loopback Iroh.
use super::*;
use arachne_security::{AdmissionAssessment, MembershipAuthorization, PendingJoin};

fn node() -> Session {
    let context = crate::context::Context::for_tests();
    let (node, receiver) = context
        .handle()
        .block_on(Node::bind_with_profile(
            ([127, 0, 0, 1], 0).into(),
            None,
            arachne_node::NetworkProfile::Direct,
            arachne_node::ConnectionBudget::default(),
        ))
        .unwrap();
    let committed = crate::committed_view::Published::new(None);
    node.set_inquiry_responder(committed.responder());
    let mut session = Session::new(
        node,
        receiver,
        context,
        committed,
        presence::Presence::new().unwrap(),
    );
    session.storage = Some(crate::StorageConfig::memory(
        &arachne_store::MemoryProvider::default(),
    ));
    session.activity = crate::WorkspaceActivity {
        phase: WorkspacePhase::Active,
        reason: None,
    };
    session
}

fn apply(workspace: &Workspace, auth: &MembershipAuthorization, commit: &[u8]) -> Workspace {
    match auth {
        MembershipAuthorization::Admission(admission) => workspace
            .prepare_admission_update(admission, commit)
            .unwrap(),
        MembershipAuthorization::AdmissionBatch(admissions) => workspace
            .prepare_admission_batch_update(admissions, commit)
            .unwrap(),
        _ => match workspace.prepare_step_update(auth, commit).unwrap() {
            PreparedManagementUpdate::Active(next) => *next,
            PreparedManagementUpdate::Removed(_) => panic!("fixture observer was removed"),
        },
    }
}

pub(super) fn grow(nodes: &[Session], size: usize) -> Vec<Workspace> {
    let creator = Workspace::create(&nodes[0].node, "Proof owner").unwrap();
    let (registration, invitation, checkpoint) =
        creator.prepare_invitation(0, false, false).unwrap();
    let joins: Vec<_> = nodes[1..3]
        .iter()
        .map(|node| {
            PendingJoin::from_invitation(
                &invitation,
                &checkpoint,
                &node.node,
                "Proof administrator",
            )
            .unwrap()
        })
        .collect();
    let requests: Vec<_> = joins
        .iter()
        .map(|join| join.admission_request().unwrap().to_vec())
        .collect();
    let validated: Vec<_> = nodes[1..3]
        .iter()
        .zip(&requests)
        .map(|(node, request)| {
            match registration
                .workspace
                .assess_admission(node.node.id(), request)
                .unwrap()
            {
                AdmissionAssessment::Ready(validated) => validated,
                _ => panic!("open invitation"),
            }
        })
        .collect();
    let entries: Vec<_> = nodes[1..3]
        .iter()
        .zip(requests.iter().zip(&validated))
        .map(|(node, (request, validated))| (node.node.id(), request.as_slice(), validated))
        .collect();
    let prepared = registration
        .workspace
        .prepare_validated_admission_batch(&entries)
        .unwrap();
    let auth = MembershipAuthorization::AdmissionBatch(
        prepared
            .replies
            .iter()
            .map(|r| r.authorization.clone())
            .collect(),
    );
    let mut others: Vec<_> = joins
        .iter()
        .map(|join| {
            let mut proof = join.join_proof().unwrap();
            proof.apply_transition(&auth, &prepared.commit).unwrap();
            join.prepare_workspace(&proof, &prepared.welcome).unwrap()
        })
        .collect();
    let mut owner = prepared.workspace;
    for member in others
        .iter()
        .map(|other| other.member().unwrap().id())
        .collect::<Vec<_>>()
    {
        let change = owner
            .prepare_management(ManagementAction::Promote(member))
            .unwrap();
        others = others
            .iter()
            .map(|other| apply(other, &change.authorization, &change.commit))
            .collect();
        owner = change.workspace;
    }
    let mut next = 0u64;
    while owner.member_count() < size {
        let (registration, invitation, checkpoint) =
            owner.prepare_invitation(0, false, false).unwrap();
        others = others
            .iter()
            .map(|other| apply(other, &registration.authorization, &registration.commit))
            .collect();
        owner = registration.workspace;
        let count = (size - owner.member_count()).min(arachne_security::MAX_ADMISSION_BATCH);
        let keys: Vec<_> = (next..next + count as u64)
            .map(|i| crate::test_key(9_000_000 + i))
            .collect();
        next += count as u64;
        let joins: Vec<_> = keys
            .iter()
            .map(|key| {
                PendingJoin::from_invitation(&invitation, &checkpoint, *key, "Proof member")
                    .unwrap()
            })
            .collect();
        let requests: Vec<_> = joins
            .iter()
            .map(|join| join.admission_request().unwrap().to_vec())
            .collect();
        let validated: Vec<_> = keys
            .iter()
            .zip(&requests)
            .map(|(key, request)| {
                use arachne_security::EndpointSigner;
                match owner.assess_admission(key.endpoint(), request).unwrap() {
                    AdmissionAssessment::Ready(validated) => validated,
                    _ => panic!("open invitation"),
                }
            })
            .collect();
        let entries: Vec<_> = keys
            .iter()
            .zip(requests.iter().zip(&validated))
            .map(|(key, (request, validated))| {
                use arachne_security::EndpointSigner;
                (key.endpoint(), request.as_slice(), validated)
            })
            .collect();
        let prepared = owner.prepare_validated_admission_batch(&entries).unwrap();
        let auth = if count == 1 {
            MembershipAuthorization::Admission(prepared.replies[0].authorization.clone())
        } else {
            MembershipAuthorization::AdmissionBatch(
                prepared
                    .replies
                    .iter()
                    .map(|r| r.authorization.clone())
                    .collect(),
            )
        };
        others = others
            .iter()
            .map(|other| apply(other, &auth, &prepared.commit))
            .collect();
        let join = |index: usize| {
            let mut proof = joins[index].join_proof().unwrap();
            proof.apply_transition(&auth, &prepared.commit).unwrap();
            joins[index]
                .prepare_workspace(&proof, &prepared.welcome)
                .unwrap()
        };
        let mut last = join(count - 1);
        owner = prepared.workspace;
        // Populate both ends of each batch's tree path, so management commits
        // remain within the existing 96 KiB cryptographic commit bound.
        if count > 1 {
            let first = join(0).prepare_self_update().unwrap();
            owner = apply(&owner, &MembershipAuthorization::SelfUpdate, &first.commit);
            others = others
                .iter()
                .map(|other| apply(other, &MembershipAuthorization::SelfUpdate, &first.commit))
                .collect();
            last = apply(&last, &MembershipAuthorization::SelfUpdate, &first.commit);
        }
        let update = last.prepare_self_update().unwrap();
        owner = apply(&owner, &MembershipAuthorization::SelfUpdate, &update.commit);
        others = others
            .iter()
            .map(|other| apply(other, &MembershipAuthorization::SelfUpdate, &update.commit))
            .collect();
        // This link served one completed batch. Disable it so large saved
        // checkpoints do not fill the separate 2 MiB live-link budget.
        let disabled = owner
            .prepare_management(ManagementAction::DisableInvitation(invitation.key()))
            .unwrap();
        others = others
            .iter()
            .map(|other| apply(other, &disabled.authorization, &disabled.commit))
            .collect();
        owner = disabled.workspace;
        if owner.member_count() >= size || next.is_multiple_of(512) {
            eprintln!("proof_capacity growing members={}", owner.member_count());
        }
    }
    let mut all = vec![owner];
    all.extend(others);
    all
}

fn request(node: &Session, peer: [u8; 32], query: &[u8]) -> Vec<u8> {
    let bytes = node
        .runtime
        .block_on(node.node.request_control(peer, query))
        .unwrap();
    assert!(bytes.len() <= arachne_node::MAX_CONTROL_REPLY);
    bytes
}

fn finish_fork(node: &mut Session) -> Value {
    let deadline = std::time::Instant::now() + Duration::from_secs(90);
    loop {
        if let Some(value) = fork::poll(node).unwrap() {
            return value;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "fork transfer did not finish"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn proof_transfer(size: usize) {
    let started = std::time::Instant::now();
    let mut nodes = vec![node(), node(), node(), node()];
    for from in &nodes {
        for to in &nodes {
            if from.node.id() != to.node.id() {
                from.runtime
                    .block_on(from.node.add_address_hint(to.node.id(), to.node.address()))
                    .unwrap();
            }
        }
    }
    let issuer = nodes[0].node.id();
    let mut states = grow(&nodes, size);
    let (registration, invitation, checkpoint) =
        states[0].prepare_invitation(0, false, false).unwrap();
    states[1] = apply(
        &states[1],
        &registration.authorization,
        &registration.commit,
    );
    states[2] = apply(
        &states[2],
        &registration.authorization,
        &registration.commit,
    );
    states[0] = registration.workspace;
    let pending =
        PendingJoin::from_invitation(&invitation, &checkpoint, &nodes[3].node, "After fork")
            .unwrap();
    for (node, state) in nodes.iter_mut().zip(states) {
        crate::persistence::commit_created(node, &state, None, None).unwrap();
        crate::session::commit_workspace(node, state);
    }
    let common = owner(&nodes[0]).epoch();
    let public_pin = owner(&nodes[0]).public_checkpoint_pin().unwrap();
    let targets: Vec<_> = owner(&nodes[0])
        .member_roster()
        .unwrap()
        .into_iter()
        .filter(|member| !member.administrator)
        .take(2)
        .map(|member| member.id)
        .collect();
    // The original link issuer always loses: invitation control at F,
    // then Remove at F+1, against the other administrator's Remove at F.
    // This also proves that pre-fork link availability survives rollback.
    stage_management(
        &mut nodes[0],
        ManagementAction::CreateInvitation([112; 32], 0, false),
    )
    .unwrap();
    adopt_staged(&mut nodes[0]);
    for index in 0..2 {
        stage_management(&mut nodes[index], ManagementAction::Remove(targets[index])).unwrap();
        adopt_staged(&mut nodes[index]);
    }
    assert!(
        owner(&nodes[0]).branch_key(common).unwrap() > owner(&nodes[1]).branch_key(common).unwrap()
    );
    nodes.swap(0, 1);
    let winner = nodes[0].node.id();
    fork::start(&mut nodes[1], winner);
    assert_eq!(
        finish_fork(&mut nodes[1])["branch_state"],
        "branch_switch_staged"
    );
    adopt_staged(&mut nodes[1]);
    let orders = fork::shared_orders(&nodes[1]);
    let (order_id, order_bytes) = orders.first_key_value().unwrap();
    assert!(order_bytes.len() > arachne_node::MAX_CONTROL_REPLY);
    eprintln!(
        "proof_capacity members={size} order_bytes={} pin_bytes={} checkpoint_bytes={} growth_ms={}",
        order_bytes.len(),
        public_pin.len(),
        owner(&nodes[0])
            .public_checkpoint_from_pin(common, &public_pin)
            .unwrap()
            .len(),
        started.elapsed().as_millis()
    );

    // Gossip announces only a reference. Its consumer retrieves the exact
    // order over Iroh and verifies it before staging quarantine.
    let reference = transfer::Reference::new(
        owner(&nodes[1]).id(),
        transfer::Object::Order(*order_id),
        order_bytes,
    )
    .unwrap();
    let mut notice = nodes[1].node.id().to_vec();
    notice.extend(reference.encode().unwrap());
    fork::receive_order_notice(&mut nodes[0], &notice);
    assert_eq!(
        finish_fork(&mut nodes[0])["branch_state"],
        "carried_revocation_received"
    );
    adopt_staged(&mut nodes[0]);
    assert!(fork::require_send(&nodes[0]).is_err());
    fork::stage_carried(&mut nodes[1]).unwrap().unwrap();
    adopt_staged(&mut nodes[1]);
    let source = nodes[1].node.id();
    let final_fingerprint = owner(&nodes[1]).epoch_fingerprint();

    // The ordinary roster query resolves the large step before stage_update.
    let owner = owner(&nodes[0]);
    let query = wire::encode_query(&wire::Query {
        workspace: owner.id(),
        basis: StateBasis::new(owner.epoch(), owner.epoch_fingerprint(), [0; 32]),
        profiles_digest: [0; 32],
        profiles: [&[], &[]],
    })
    .unwrap();
    let bytes = request(&nodes[0], source, &query);
    let expanded = nodes[0]
        .runtime
        .block_on(wire::resolve_reply(
            nodes[0].node.control_client(),
            source,
            &bytes,
        ))
        .unwrap();
    assert!(expanded.len() > arachne_node::MAX_CONTROL_REPLY);
    let reply = wire::decode_resolved_reply(&expanded).unwrap();
    stage_update(
        &mut nodes[0],
        serde_json::from_value(reply["step"].clone()).unwrap(),
    )
    .unwrap();
    adopt_staged(&mut nodes[0]);
    assert_eq!(
        super::owner(&nodes[0]).epoch_fingerprint(),
        final_fingerprint
    );

    // Normal range catch-up resolves both steps. A provisional verifier
    // reaches the winner; the native observer adopts only the first here.
    let query = wire::encode_range_query(&wire::RangeQuery {
        workspace: super::owner(&nodes[2]).id(),
        after: common,
        until: common + 2,
    })
    .unwrap();
    let bytes = request(&nodes[2], source, &query);
    let expanded = nodes[2]
        .runtime
        .block_on(wire::resolve_range_reply(
            nodes[2].node.control_client(),
            source,
            &bytes,
        ))
        .unwrap();
    let page = wire::decode_resolved_range_reply(&expanded).unwrap();
    assert_eq!(page.steps.len(), 2);
    let mut verified = super::owner(&nodes[2]).provisional_copy().unwrap();
    for bytes in &page.steps {
        let (auth, commit) = join_step_from_wire(bytes).unwrap().parts().unwrap();
        verified = apply(&verified, &auth, &commit);
    }
    assert_eq!(verified.epoch_fingerprint(), final_fingerprint);
    stage_update(&mut nodes[2], join_step_from_wire(page.steps[0]).unwrap()).unwrap();
    adopt_staged(&mut nodes[2]);
    stage_management(
        &mut nodes[2],
        ManagementAction::CreateInvitation([113; 32], 0, false),
    )
    .unwrap();
    adopt_staged(&mut nodes[2]);
    // The first difference now IS the large proof-bearing step. Fork pull
    // uses the same fragment resolver and durable snapshot switch.
    fork::start(&mut nodes[2], source);
    assert_eq!(
        finish_fork(&mut nodes[2])["branch_state"],
        "branch_switch_staged"
    );
    adopt_staged(&mut nodes[2]);
    assert_eq!(
        super::owner(&nodes[2]).epoch_fingerprint(),
        final_fingerprint
    );

    // A later join replays the large carried proof from its pre-fork link.
    let server = nodes
        .iter()
        .position(|node| node.node.id() == issuer)
        .unwrap();
    let request_bytes = pending.admission_request().unwrap();
    let joiner = nodes[3].node.id();
    crate::ops::admission::stage_admission(
        &mut nodes[server],
        joiner,
        request_bytes,
        Some(&checkpoint),
        None,
    )
    .unwrap();
    adopt_staged(&mut nodes[server]);
    let mut query =
        crate::ops::admission::admission_request_packet(request_bytes, b"After fork").unwrap();
    let mut proof = pending.join_proof().unwrap();
    let mut pages = 0;
    let mut fragmented = false;
    loop {
        let bytes = request(&nodes[3], issuer, &query);
        let (reply, expanded) = nodes[3]
            .runtime
            .block_on(crate::ops::admission::resolve_admission_reply(
                nodes[3].node.control_client(),
                issuer,
                &bytes,
            ))
            .unwrap();
        fragmented |= expanded > arachne_node::MAX_CONTROL_REPLY;
        for step in reply["commits"].as_array().unwrap() {
            let step: JoinStep = serde_json::from_value(step.clone()).unwrap();
            let (auth, commit) = step.parts().unwrap();
            proof.apply_transition(&auth, &commit).unwrap();
        }
        pages += 1;
        assert!(pages <= 8);
        if reply
            .get("history_complete")
            .and_then(Value::as_bool)
            .unwrap_or(true)
        {
            let welcome: Vec<u8> = serde_json::from_value(reply["welcome"].clone()).unwrap();
            let joined = pending.prepare_workspace(&proof, &welcome).unwrap();
            assert_eq!(joined.member_count(), size - 1);
            assert_eq!(
                joined.epoch_fingerprint(),
                super::owner(&nodes[server]).epoch_fingerprint()
            );
            break;
        }
        query = crate::ops::admission::admission_history_page_packet(
            request_bytes,
            reply["history_next"].as_u64().unwrap() as usize,
        )
        .unwrap();
    }
    assert!(fragmented);
    eprintln!(
        "proof_capacity members={size} admission_pages={pages} total_ms={}",
        started.elapsed().as_millis()
    );
}

#[test]
fn large_proofs_cross_queries_ranges_forks_orders_and_admission() {
    proof_transfer(513);
}

#[test]
#[ignore = "2,049-member native store and proof transfer capacity check"]
fn two_thousand_members_transfer_large_proofs_through_all_consumers() {
    proof_transfer(2049);
}
