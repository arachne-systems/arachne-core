use std::{collections::BTreeMap, time::Duration};

use arachne_node::{Node, Permissions, Topic};

/// A membership step for a batch of 16 admissions is larger than a data
/// publication may be. The overlay used one 16 KiB payload bound for both, so
/// every member dropped batch steps and caught up only by pull (tablets: epochs
/// 5-7, the 16-member batches, never arrived by gossip; 2026-09-18). Membership
/// messages now take up to a frame; data publications keep 16 KiB.
#[tokio::test]
async fn a_large_membership_message_crosses_the_overlay_and_data_stays_bounded() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let (a, _) = Node::bind_with_identity("127.0.0.1:0".parse().unwrap(), &[81; 32]).await.unwrap();
        let (b, _b_events) = Node::bind_with_identity("127.0.0.1:0".parse().unwrap(), &[82; 32]).await.unwrap();
        let workspace = [55; 32];
        let policy = BTreeMap::from([(a.id(), Permissions::AllTopics), (b.id(), Permissions::AllTopics)]);
        for node in [&a, &b] {
            node.install_verified_policy(workspace, 1, policy.clone()).await.unwrap();
        }
        a.add_address_hint(b.id(), b.address()).await.unwrap();
        b.add_address_hint(a.id(), a.address()).await.unwrap();
        a.enable_gossip(workspace, 1).await.unwrap();
        b.enable_gossip(workspace, 1).await.unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while !b.live_neighbors(workspace).await.contains(&a.id()) {
            assert!(tokio::time::Instant::now() < deadline, "the overlay never joined");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        let step = vec![7u8; 40 * 1024];
        assert!(a.broadcast_membership(workspace, step.clone()).await.unwrap());
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let received = loop {
            if let Some(message) = b.poll_membership_gossip() {
                break message;
            }
            assert!(tokio::time::Instant::now() < deadline, "a 40 KB membership message did not arrive");
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        assert_eq!(received, (workspace, step));

        // Data publications keep their bound.
        let data = a.publish(workspace, 1, Topic::new("streams/opaque").unwrap(), vec![1u8; 40 * 1024]).await;
        assert!(data.is_err(), "a 40 KB data publication must still be refused");
    })
    .await
    .unwrap();
}
