use std::{collections::BTreeMap, time::Duration};

use arachne_node::{Node, Permissions};

/// An overlay chose its first contacts by roster order. After a wave of
/// joiners that are offline now, those were offline peers, and a tablet (BIG
/// RED) never joined the live members' swarm: it received 3 gossip messages and
/// then none while JOSA received 56 (2026-09-18). Peers with a known address
/// must come first.
#[tokio::test]
async fn an_overlay_joins_the_live_peer_among_many_offline_members() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let (a, _) = Node::bind_with_identity("127.0.0.1:0".parse().unwrap(), &[91; 32]).await.unwrap();
        let (b, _) = Node::bind_with_identity("127.0.0.1:0".parse().unwrap(), &[92; 32]).await.unwrap();
        let workspace = [66; 32];
        let mut policy = BTreeMap::from([(a.id(), Permissions::AllTopics), (b.id(), Permissions::AllTopics)]);
        for seed in 0..24u8 {
            let offline = *iroh::SecretKey::from_bytes(&[seed.wrapping_add(1); 32]).public().as_bytes();
            policy.insert(offline, Permissions::AllTopics);
        }
        for node in [&a, &b] {
            node.install_verified_policy(workspace, 1, policy.clone()).await.unwrap();
        }
        // As on tablets: only one side knows where the other is.
        b.add_address_hint(a.id(), a.address()).await.unwrap();
        a.enable_gossip(workspace, 1).await.unwrap();
        b.enable_gossip(workspace, 1).await.unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
        while !b.live_neighbors(workspace).await.contains(&a.id()) {
            assert!(tokio::time::Instant::now() < deadline, "the overlay never reached the live peer");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
}
