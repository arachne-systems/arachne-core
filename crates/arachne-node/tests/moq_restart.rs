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
    std::fs::create_dir(root).unwrap();
    let config = root.join("config.json");
    std::fs::write(
        &config,
        serde_json::to_vec(&serde_json::json!({
            "secret": secret,
            "parent": parent.id(),
            "address": parent.address().to_string(),
        }))
        .unwrap(),
    )
    .unwrap();
    PeerProcess(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "restarted_peer_process",
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
#[ignore = "subprocess helper for the restart test"]
async fn restarted_peer_process() {
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
    node.install_verified_policy(
        WORKSPACE,
        1,
        BTreeMap::from([
            (node.id(), Permissions::AllTopics),
            (parent, Permissions::AllTopics),
        ]),
    )
    .await
    .unwrap();
    let topic = Topic::new("shared/stream").unwrap();
    node.subscribe(WORKSPACE, 1, topic.clone()).await.unwrap();
    node.enable_moq_delivery(WORKSPACE, 1, parent, topic.clone())
        .await
        .unwrap();
    std::fs::write(root.join("address"), node.address().to_string()).unwrap();
    while node.moq_metrics().sessions_active == 0 {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    std::fs::write(root.join("ready"), b"ready").unwrap();
    let mut sequence = 0;
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
