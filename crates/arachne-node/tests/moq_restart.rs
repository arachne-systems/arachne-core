#![cfg(feature = "moq")]

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::Duration,
};

use arachne_node::{DeliveryClass, Node, Permissions, Topic};

const WORKSPACE: [u8; 32] = [49; 32];
const CHILD_CONFIG: &str = "ARACHNE_MOQ_RESTART_TEST_CONFIG";

struct PeerProcess(Child);

impl Drop for PeerProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn_peer(root: &Path, secret: [u8; 32], parent: &Node) -> PeerProcess {
    spawn_peer_with_witness(root, secret, parent, None, 0, false, Duration::ZERO)
}

fn spawn_peer_with_witness(
    root: &Path,
    secret: [u8; 32],
    parent: &Node,
    witness: Option<&Node>,
    sequence: u64,
    proactive: bool,
    cadence: Duration,
) -> PeerProcess {
    std::fs::create_dir(root).unwrap();
    let config = root.join("config.json");
    std::fs::write(
        &config,
        serde_json::to_vec(&serde_json::json!({
            "secret": secret,
            "parent": parent.id(),
            "address": parent.address().to_string(),
            "witness": witness.map(|node| (node.id(), node.address().to_string())),
            "sequence": sequence,
            "proactive": proactive,
            "cadence_ms": cadence.as_millis() as u64,
        }))
        .unwrap(),
    )
    .unwrap();
    PeerProcess(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                if proactive { "restarted_peer_process_multithread" } else { "restarted_peer_process" },
                "--nocapture",
            ])
            .env(CHILD_CONFIG, config)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    )
}

async fn wait_file(path: &Path) {
    while !path.exists() {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn either_peer_can_restore_a_stream_after_an_unannounced_restart() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let mut secrets = [[71; 32], [72; 32]];
        secrets.sort_by_key(|secret| iroh::SecretKey::from_bytes(secret).public());
        let peer_id = *iroh::SecretKey::from_bytes(&secrets[1]).public().as_bytes();
        let (parent, mut messages) =
            Node::bind_with_identity("127.0.0.1:0".parse().unwrap(), &secrets[0])
                .await
                .unwrap();
        parent
            .install_verified_policy(
                WORKSPACE,
                1,
                BTreeMap::from([
                    (parent.id(), Permissions::AllTopics),
                    (peer_id, Permissions::AllTopics),
                ]),
            )
            .await
            .unwrap();
        let topic = Topic::new("shared/stream").unwrap();
        parent.subscribe(WORKSPACE, 1, topic.clone()).await.unwrap();
        let root = tempfile::tempdir().unwrap();
        let first = root.path().join("first");
        let child = spawn_peer(&first, secrets[1], &parent);
        wait_file(&first.join("address")).await;
        let address = std::fs::read_to_string(first.join("address")).unwrap();
        parent
            .add_address_hint(peer_id, address.parse().unwrap())
            .await
            .unwrap();
        parent
            .enable_moq_delivery(WORKSPACE, 1, peer_id, topic.clone())
            .await
            .unwrap();
        wait_file(&first.join("ready")).await;
        while parent.moq_metrics().sessions_active == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // SIGKILL sends no QUIC close. The new process keeps its identity but
        // binds a new port, as an Android force-stop and launch do.
        drop(child);
        let second = root.path().join("second");
        let child = spawn_peer(&second, secrets[1], &parent);
        wait_file(&second.join("address")).await;
        let address = std::fs::read_to_string(second.join("address")).unwrap();
        parent
            .add_address_hint(peer_id, address.parse().unwrap())
            .await
            .unwrap();
        let restored = tokio::time::timeout(Duration::from_secs(3), async {
            wait_file(&second.join("ready")).await;
            parent
                .publish_protected_with_class(
                    WORKSPACE,
                    1,
                    topic,
                    1,
                    DeliveryClass::Critical,
                    b"after restart".to_vec(),
                )
                .await
                .unwrap();
            loop {
                let message = messages.recv().await.unwrap();
                if message.sender == peer_id && message.payload == b"after restart" {
                    break;
                }
            }
        })
        .await;
        drop(child);
        parent.close().await;
        assert!(
            restored.is_ok(),
            "restarted listener waited for the old QUIC session to expire"
        );
    })
    .await
    .expect("stream restart fixture timed out");
}

#[tokio::test]
async fn repeated_restart_delivers_the_whole_burst_with_a_third_peer() {
    three_peer_restarts(Duration::ZERO, false).await;
}

#[tokio::test]
async fn repeated_restart_delivers_paced_packets_with_a_third_peer() {
    three_peer_restarts(Duration::from_millis(75), false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn restarted_peer_can_publish_before_any_peer_packet_arrives() {
    three_peer_restarts(Duration::from_millis(75), true).await;
}

async fn three_peer_restarts(cadence: Duration, proactive: bool) {
    tokio::time::timeout(Duration::from_secs(45), async {
        let secrets = [[81; 32], [82; 32], [83; 32]];
        let child_id = *iroh::SecretKey::from_bytes(&secrets[2]).public().as_bytes();
        let (parent, mut parent_messages) =
            Node::bind_with_identity("127.0.0.1:0".parse().unwrap(), &secrets[0])
                .await
                .unwrap();
        let (witness, mut witness_messages) =
            Node::bind_with_identity("127.0.0.1:0".parse().unwrap(), &secrets[1])
                .await
                .unwrap();
        let policy = BTreeMap::from([
            (parent.id(), Permissions::AllTopics),
            (witness.id(), Permissions::AllTopics),
            (child_id, Permissions::AllTopics),
        ]);
        let topic = Topic::new("shared/stream").unwrap();
        for (node, other) in [(&parent, &witness), (&witness, &parent)] {
            node.install_verified_policy(WORKSPACE, 1, policy.clone()).await.unwrap();
            node.subscribe(WORKSPACE, 1, topic.clone()).await.unwrap();
            node.add_address_hint(other.id(), other.address()).await.unwrap();
            node.enable_moq_delivery(WORKSPACE, 1, other.id(), topic.clone()).await.unwrap();
        }
        let root = tempfile::tempdir().unwrap();
        for round in 0..12u64 {
            let directory = root.path().join(format!("restart-{round}"));
            let child = spawn_peer_with_witness(
                &directory, secrets[2], &parent, Some(&witness), round * 1000, proactive, cadence,
            );
            wait_file(&directory.join("address")).await;
            let address = std::fs::read_to_string(directory.join("address")).unwrap();
            for node in [&parent, &witness] {
                node.add_address_hint(child_id, address.parse().unwrap()).await.unwrap();
                node.enable_moq_delivery(WORKSPACE, 1, child_id, topic.clone()).await.unwrap();
            }
            let mut parent_received = std::collections::BTreeSet::new();
            let mut witness_received = std::collections::BTreeSet::new();
            let result = tokio::time::timeout(Duration::from_secs(3), async {
                // This is the app harness's aggregate readiness condition for
                // two selected tablets in a three-member workspace. There is
                // deliberately no settling delay before the first publication.
                wait_file(&directory.join("ready")).await;
                while parent.moq_metrics().sessions_active == 0 {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                for packet in 0..if proactive { 0 } else { 13u8 } {
                    let mut payload = vec![0; 2048];
                    payload[..2].copy_from_slice(&[round as u8, packet]);
                    parent.publish_protected_with_class(
                        WORKSPACE, 1, topic.clone(), round * 13 + u64::from(packet) + 1,
                        DeliveryClass::Critical, payload,
                    ).await.unwrap();
                    if !cadence.is_zero() {
                        tokio::time::sleep(cadence).await;
                    }
                }
                while parent_received.len() != 13 || witness_received.len() != 13 {
                    tokio::select! {
                        message = parent_messages.recv() => {
                            let message = message.unwrap();
                            if message.sender == child_id && message.payload.first() == Some(&(round as u8)) {
                                parent_received.insert(message.payload[1]);
                            }
                        }
                        message = witness_messages.recv() => {
                            let message = message.unwrap();
                            if message.sender == child_id && message.payload.first() == Some(&(round as u8)) {
                                witness_received.insert(message.payload[1]);
                            }
                        }
                    }
                }
            }).await;
            drop(child);
            assert!(result.is_ok(), "restart {round}: parent got {parent_received:?}, witness got {witness_received:?}; parent metrics {:?}, witness metrics {:?}", parent.moq_metrics(), witness.moq_metrics());
        }
        parent.close().await;
        witness.close().await;
    }).await.expect("three-peer restart fixture timed out");
}

#[tokio::test]
#[ignore = "subprocess helper for the restart test"]
async fn restarted_peer_process() {
    peer_process().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "subprocess helper for the restart test"]
async fn restarted_peer_process_multithread() {
    peer_process().await;
}

async fn peer_process() {
    let config =
        PathBuf::from(std::env::var_os(CHILD_CONFIG).expect("parent supplies the fixture"));
    let root = config.parent().unwrap();
    let config: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&config).unwrap()).unwrap();
    let secret = serde_json::from_value::<[u8; 32]>(config["secret"].clone()).unwrap();
    let parent = serde_json::from_value::<[u8; 32]>(config["parent"].clone()).unwrap();
    let (node, mut messages) = Node::bind_with_identity("127.0.0.1:0".parse().unwrap(), &secret)
        .await
        .unwrap();
    node.add_address_hint(parent, config["address"].as_str().unwrap().parse().unwrap())
        .await
        .unwrap();
    let witness: Option<([u8; 32], String)> =
        serde_json::from_value(config["witness"].clone()).unwrap();
    let mut policy = BTreeMap::from([
        (node.id(), Permissions::AllTopics),
        (parent, Permissions::AllTopics),
    ]);
    if let Some((peer, address)) = &witness {
        policy.insert(*peer, Permissions::AllTopics);
        node.add_address_hint(*peer, address.parse().unwrap())
            .await
            .unwrap();
    }
    node.install_verified_policy(WORKSPACE, 1, policy)
        .await
        .unwrap();
    let topic = Topic::new("shared/stream").unwrap();
    node.subscribe(WORKSPACE, 1, topic.clone()).await.unwrap();
    node.enable_moq_delivery(WORKSPACE, 1, parent, topic.clone())
        .await
        .unwrap();
    if let Some((peer, _)) = witness {
        node.enable_moq_delivery(WORKSPACE, 1, peer, topic.clone())
            .await
            .unwrap();
    }
    std::fs::write(root.join("address"), node.address().to_string()).unwrap();
    while node.moq_metrics().sessions_active == 0 {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    std::fs::write(root.join("ready"), b"ready").unwrap();
    let mut sequence = config["sequence"].as_u64().unwrap();
    if config["proactive"].as_bool().unwrap() {
        let round = (sequence / 1000) as u8;
        let cadence = Duration::from_millis(config["cadence_ms"].as_u64().unwrap());
        for packet in 0..13u8 {
            sequence += 1;
            let mut payload = vec![0; 2048];
            payload[..2].copy_from_slice(&[round, packet]);
            node.publish_protected_with_class(
                WORKSPACE, 1, topic.clone(), sequence, DeliveryClass::Critical, payload,
            ).await.unwrap();
            if !cadence.is_zero() {
                tokio::time::sleep(cadence).await;
            }
        }
    }
    loop {
        let message = messages.recv().await.unwrap();
        if message.sender == parent {
            sequence += 1;
            node.publish_protected_with_class(
                WORKSPACE,
                1,
                topic.clone(),
                sequence,
                DeliveryClass::Critical,
                message.payload,
            )
            .await
            .unwrap();
        }
    }
}
