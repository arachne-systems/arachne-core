//! Real local discovery, no manually injected addresses. Requires multicast-capable LAN.
use arachne_node::{Node, Permissions, Topic};
use std::{collections::BTreeMap, time::Duration};

#[tokio::test]
async fn saved_identities_rediscover_after_both_sockets_change() {
    tokio::time::timeout(Duration::from_secs(45), async {
        let seeds = [
            iroh::SecretKey::generate().to_bytes(),
            iroh::SecretKey::generate().to_bytes(),
        ];
        let mut identities = None;
        let mut old_ports = Vec::new();
        for generation in 0..2 {
            let (a, _) = Node::bind_lan_with_identity("0.0.0.0:0".parse().unwrap(), &seeds[0])
                .await
                .unwrap();
            let (b, mut incoming) =
                Node::bind_lan_with_identity("0.0.0.0:0".parse().unwrap(), &seeds[1])
                    .await
                    .unwrap();
            assert!(!old_ports.contains(&a.address().port()));
            assert!(!old_ports.contains(&b.address().port()));
            let ids = [a.id(), b.id()];
            if let Some(previous) = identities {
                assert_eq!(ids, previous);
            }
            identities = Some(ids);
            assert_ne!(ids[0], ids[1]);
            assert!(a.address_hint(b.id()).await.is_none());
            assert!(b.address_hint(a.id()).await.is_none());
            let topic = Topic::new("streams/restart").unwrap();
            let policy = BTreeMap::from([
                (a.id(), Permissions::AllTopics),
                (b.id(), Permissions::AllTopics),
            ]);
            for node in [&a, &b] {
                node.install_verified_policy([1; 32], 1, policy.clone())
                    .await
                    .unwrap();
            }
            let report = b.subscribe([1; 32], 1, topic.clone()).await.unwrap();
            assert!(
                report.failed.is_empty(),
                "discovery subscription failed: {report:?}"
            );
            assert!(report.admitted.contains(&a.id()));
            // Only an authenticated authorized subscription populates the return route.
            assert!(a.address_hint(b.id()).await.is_some());
            let payload = vec![generation, 0, 255];
            let report = a.publish([1; 32], 1, topic, payload.clone()).await.unwrap();
            assert!(report.failed.is_empty());
            assert!(report.admitted.contains(&b.id()));
            let received = tokio::time::timeout(Duration::from_secs(5), incoming.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(received.sender, a.id());
            assert_eq!(received.payload, payload);
            old_ports = vec![a.address().port(), b.address().port()];
            a.close().await;
            b.close().await;
        }
    })
    .await
    .expect("LAN restart check exceeded 45 seconds");
}
