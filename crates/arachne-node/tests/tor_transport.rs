#![cfg(feature = "tor")]

use arachne_node::{NetworkProfile, Node, Permissions, Topic};
use std::{collections::BTreeMap, time::Duration};

/// Requires a Tor daemon with SOCKS5 on 9050 and ControlPort on 9051.
#[tokio::test]
#[ignore = "requires a local Tor daemon and Tor network access"]
async fn tor_only_nodes_exchange_a_pubsub_message() {
    tokio::time::timeout(Duration::from_secs(300), async {
        let (a, _) = Node::bind_with_profile(
            "0.0.0.0:0".parse().unwrap(),
            Some(&[71; 32]),
            NetworkProfile::Tor,
            Default::default(),
        )
        .await
        .unwrap();
        let (b, mut incoming) = Node::bind_with_profile(
            "0.0.0.0:0".parse().unwrap(),
            Some(&[72; 32]),
            NetworkProfile::Tor,
            Default::default(),
        )
        .await
        .unwrap();
        let workspace = [73; 32];
        let topic = Topic::new("streams/tor-check").unwrap();
        let policy = BTreeMap::from([
            (a.id(), Permissions::AllTopics),
            (b.id(), Permissions::AllTopics),
        ]);
        for node in [&a, &b] {
            node.install_verified_policy(workspace, 1, policy.clone())
                .await
                .unwrap();
        }

        let subscription = b.subscribe(workspace, 1, topic.clone()).await.unwrap();
        assert!(subscription.failed.is_empty(), "{subscription:?}");
        assert!(subscription.admitted.contains(&a.id()));

        let payload = b"core-tor-transport".to_vec();
        let publication = a
            .publish(workspace, 1, topic, payload.clone())
            .await
            .unwrap();
        assert!(publication.failed.is_empty(), "{publication:?}");
        assert!(publication.admitted.contains(&b.id()));
        let received = tokio::time::timeout(Duration::from_secs(10), incoming.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received.sender, a.id());
        assert_eq!(received.payload, payload);

        let paths = a.transport_metrics().paths;
        assert!(paths.iter().any(|path| path.endpoint == b.id()));
        assert!(paths.iter().all(|path| path.route == "tor"), "{paths:?}");
        a.close().await;
        b.close().await;
    })
    .await
    .expect("Tor pub/sub check exceeded five minutes");
}
