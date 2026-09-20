//! Real Iroh protected pub/sub assembly, no ATAK types or injected member keys.
//! Run with a NEW repository-local state directory. Endpoint roots live only in
//! memory: this is an integration check, not a deployable credential store.
use arachne_node::{Message, MessageReceiver, Node, Permissions, Topic};
use arachne_routing::PublicationContext;
use arachne_security::{ApplicationMessage, PendingJoin, StorageKey, Workspace};
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::Write,
    path::Path,
    time::Duration,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const REVISION: u64 = 17; // Local default-policy revision, deliberately not MLS epoch.

fn persist(owner: &Workspace, key: &StorageKey, file: &Path) -> Result<()> {
    let snapshot = owner.seal(key)?;
    let temporary = file.with_extension("new");
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    output.write_all(&snapshot)?;
    output.sync_all()?;
    drop(output);
    fs::rename(&temporary, file)?;
    File::open(file.parent().ok_or("missing state directory")?)?.sync_all()?;
    assert_eq!(fs::read(file)?, snapshot);
    Ok(())
}

fn policy(owner: &Workspace, topics: &BTreeSet<Topic>) -> Result<BTreeMap<[u8; 32], Permissions>> {
    let endpoints = owner.member_endpoints()?;
    let result: BTreeMap<_, _> = endpoints
        .iter()
        .map(|endpoint| {
            (
                *endpoint,
                Permissions::Selected {
                    publish: topics.clone(),
                    subscribe: topics.clone(),
                },
            )
        })
        .collect();
    if result.len() != endpoints.len() {
        return Err("duplicate member endpoint".into());
    }
    Ok(result)
}

fn authenticate(
    owner: &Workspace,
    key: &StorageKey,
    node_id: [u8; 32],
    incoming: &Message,
) -> Result<(Workspace, ApplicationMessage, PublicationContext)> {
    if incoming.workspace != owner.id() {
        return Err("wrong workspace".into());
    }
    let (context, ciphertext) = PublicationContext::unpack(
        incoming.workspace,
        incoming.revision,
        incoming.topic.clone(),
        &incoming.payload,
    )?;
    let mut candidate = Workspace::restore(key, node_id, owner.id(), &owner.seal(key)?)?;
    let plaintext = candidate.unprotect_application(&context.authenticated_bytes(), ciphertext)?;
    // Node currently supports direct transport, not forwarding. A future relay
    // adapter must separately authorize the hop and the authenticated author.
    if plaintext.endpoint != incoming.sender {
        return Err("direct author mismatch".into());
    }
    Ok((candidate, plaintext, context))
}

async fn next(receiver: &mut MessageReceiver) -> Result<Message> {
    Ok(
        tokio::time::timeout(Duration::from_secs(5), receiver.recv())
            .await?
            .ok_or("consumer closed")?,
    )
}

#[tokio::main]
async fn main() -> Result<()> {
    let directory = std::env::args_os()
        .nth(1)
        .ok_or("supply a NEW repository-local state directory")?;
    let directory = Path::new(&directory);
    fs::create_dir(directory)?; // Never overwrite an earlier run or user state.
    let alice_root = iroh::SecretKey::generate();
    let bob_root = iroh::SecretKey::generate();
    let (alice, mut alice_events) =
        Node::bind_with_identity("127.0.0.1:0".parse()?, &alice_root.to_bytes()).await?;
    let (bob, mut bob_events) =
        Node::bind_with_identity("127.0.0.1:0".parse()?, &bob_root.to_bytes()).await?;
    let (outsider, _outsider_events) = Node::bind("127.0.0.1:0".parse()?).await?;
    let alice_key = StorageKey::derive(&alice_root.to_bytes())?;
    let bob_key = StorageKey::derive(&bob_root.to_bytes())?;
    let admin = Workspace::create(alice.id(), "Stream publisher")?;
    let (invitation, checkpoint) = admin.issue_invitation()?;
    let pending =
        PendingJoin::from_invitation(&invitation, &checkpoint, bob.id(), "Stream subscriber")?;
    let prepared = admin.prepare_admission(bob.id(), pending.admission_request()?)?;
    let mut proof = pending.join_proof()?;
    proof.apply_add(&prepared.authorization, &prepared.commit)?;
    let mut bob_group = pending.prepare_workspace(&proof, &prepared.welcome)?;
    let mut alice_group = prepared.workspace;
    let workspace = alice_group.id();
    let alice_file = directory.join("publisher.bin");
    let bob_file = directory.join("subscriber.bin");
    persist(&alice_group, &alice_key, &alice_file)?;
    persist(&bob_group, &bob_key, &bob_file)?;
    assert_ne!(alice_group.epoch(), REVISION);
    let topic = Topic::new("streams/sample")?;
    let other = Topic::new("streams/other")?;
    let replies = Topic::new("streams/replies")?;
    let topics = BTreeSet::from([topic.clone(), other.clone(), replies.clone()]);
    let alice_policy = policy(&alice_group, &topics)?;
    let bob_policy = policy(&bob_group, &topics)?;
    assert_eq!(
        alice_policy.keys().collect::<Vec<_>>(),
        bob_policy.keys().collect::<Vec<_>>()
    );
    assert!(!alice_policy.contains_key(&outsider.id()));
    alice
        .install_verified_policy(workspace, REVISION, alice_policy)
        .await?;
    bob.install_verified_policy(workspace, REVISION, bob_policy)
        .await?;
    alice.add_address_hint(bob.id(), bob.address()).await?;
    bob.add_address_hint(alice.id(), alice.address()).await?;
    for interest in [topic.clone(), other.clone()] {
        assert!(
            bob.subscribe(workspace, REVISION, interest)
                .await?
                .failed
                .is_empty()
        );
    }
    assert!(
        alice
            .subscribe(workspace, REVISION, replies.clone())
            .await?
            .failed
            .is_empty()
    );
    // An attacker can lie in its OWN local policy. It cannot add itself to the
    // verified roster installed at either legitimate receiver.
    let mut forged = policy(&alice_group, &topics)?;
    forged.insert(
        outsider.id(),
        Permissions::Selected {
            publish: topics.clone(),
            subscribe: topics.clone(),
        },
    );
    outsider
        .install_verified_policy(workspace, REVISION, forged)
        .await?;
    outsider
        .add_address_hint(alice.id(), alice.address())
        .await?;
    outsider.add_address_hint(bob.id(), bob.address()).await?;
    let rejected = outsider
        .subscribe(workspace, REVISION, topic.clone())
        .await?;
    assert_eq!(rejected.failed.len(), 2);
    assert_eq!(rejected.admitted, vec![outsider.id()]);

    let context = PublicationContext {
        sequence: None,
        workspace,
        revision: REVISION,
        topic: topic.clone(),
        id: 1u128.to_be_bytes(),
    };
    let payload = b"opaque binary observation\x00\xff";
    let ciphertext = alice_group.protect_application(&context.authenticated_bytes(), payload)?;
    persist(&alice_group, &alice_key, &alice_file)?; // Commit ratchet BEFORE network release.
    let packet = context.packet(&ciphertext)?;
    let wrong_topic = alice
        .publish(workspace, REVISION, other, packet.clone())
        .await?;
    assert_eq!(wrong_topic.admitted, vec![bob.id()]);
    assert!(
        authenticate(
            &bob_group,
            &bob_key,
            bob.id(),
            &next(&mut bob_events).await?
        )
        .is_err()
    );
    let mut changed_id = packet.clone();
    changed_id[5] ^= 1;
    alice
        .publish(workspace, REVISION, topic.clone(), changed_id)
        .await?;
    assert!(
        authenticate(
            &bob_group,
            &bob_key,
            bob.id(),
            &next(&mut bob_events).await?
        )
        .is_err()
    );
    let sent = alice
        .publish(workspace, REVISION, topic.clone(), packet.clone())
        .await?;
    assert_eq!(sent.admitted, vec![bob.id()]);
    assert!(sent.failed.is_empty());
    let (candidate, received, identity) = authenticate(
        &bob_group,
        &bob_key,
        bob.id(),
        &next(&mut bob_events).await?,
    )?;
    persist(&candidate, &bob_key, &bob_file)?; // Commit replay state BEFORE application delivery.
    drop(candidate);
    assert_eq!(received.payload, payload);
    assert_eq!(identity.id, context.id);
    assert_eq!(
        received.member,
        alice_group.member().ok_or("missing sender")?.id()
    );
    bob_group = Workspace::restore(&bob_key, bob.id(), workspace, &fs::read(&bob_file)?)?;
    alice
        .publish(workspace, REVISION, topic.clone(), packet)
        .await?;
    assert!(
        authenticate(
            &bob_group,
            &bob_key,
            bob.id(),
            &next(&mut bob_events).await?
        )
        .is_err()
    );
    assert!(
        bob.unsubscribe(workspace, REVISION, topic.clone())
            .await?
            .failed
            .is_empty()
    );
    let skipped = PublicationContext {
        sequence: None,
        workspace,
        revision: REVISION,
        topic: topic.clone(),
        id: 2u128.to_be_bytes(),
    };
    let ciphertext =
        alice_group.protect_application(&skipped.authenticated_bytes(), b"not subscribed")?;
    persist(&alice_group, &alice_key, &alice_file)?;
    let absent = alice
        .publish(
            workspace,
            REVISION,
            topic.clone(),
            skipped.packet(&ciphertext)?,
        )
        .await?;
    assert!(absent.admitted.is_empty() && absent.failed.is_empty());
    assert!(bob_events.try_recv().is_err());
    assert!(
        bob.subscribe(workspace, REVISION, topic.clone())
            .await?
            .failed
            .is_empty()
    );
    let large_context = PublicationContext {
        sequence: None,
        workspace,
        revision: REVISION,
        topic: topic.clone(),
        id: 3u128.to_be_bytes(),
    };
    let large_payload = vec![0x9f; arachne_security::MAX_APPLICATION_PAYLOAD];
    let ciphertext =
        alice_group.protect_application(&large_context.authenticated_bytes(), &large_payload)?;
    persist(&alice_group, &alice_key, &alice_file)?;
    let sent = alice
        .publish(
            workspace,
            REVISION,
            topic,
            large_context.packet(&ciphertext)?,
        )
        .await?;
    assert_eq!(sent.admitted, vec![bob.id()]);
    assert!(sent.failed.is_empty());
    let (candidate, received, _) = authenticate(
        &bob_group,
        &bob_key,
        bob.id(),
        &next(&mut bob_events).await?,
    )?;
    persist(&candidate, &bob_key, &bob_file)?;
    bob_group = candidate;
    assert_eq!(received.payload, large_payload);
    let reverse = PublicationContext {
        sequence: None,
        workspace,
        revision: REVISION,
        topic: replies.clone(),
        id: 4u128.to_be_bytes(),
    };
    let reply = br#"{"status":"subscribed","format":"opaque"}"#;
    let ciphertext = bob_group.protect_application(&reverse.authenticated_bytes(), reply)?;
    persist(&bob_group, &bob_key, &bob_file)?;
    let sent = bob
        .publish(workspace, REVISION, replies, reverse.packet(&ciphertext)?)
        .await?;
    assert_eq!(sent.admitted, vec![alice.id()]);
    assert!(sent.failed.is_empty());
    let (candidate, received, _) = authenticate(
        &alice_group,
        &alice_key,
        alice.id(),
        &next(&mut alice_events).await?,
    )?;
    persist(&candidate, &alice_key, &alice_file)?;
    assert_eq!(received.payload, reply);
    alice.close().await;
    bob.close().await;
    outsider.close().await;
    println!(
        "{}",
        json!({"passed":true,"scope":"Three independent Iroh endpoints in one host process on loopback; admission cryptography in process; no ATAK", "binary_delivery":true,"reverse_json_delivery":true,"membership_derived_endpoints":true,"unauthorized_subscription_rejected":true,"topic_substitution_rejected":true,"publication_id_substitution_rejected":true,"replay_after_restore_rejected":true,"unsubscribe_no_recipients":true,"resubscribe_large_binary_delivery":true,"unsubscribed_generation_skipped":1,"largest_plaintext_bytes":arachne_security::MAX_APPLICATION_PAYLOAD,"state_directory":directory.display().to_string(),"endpoint_roots":"ephemeral RAM only; not a deployable credential store"})
    );
    Ok(())
}
