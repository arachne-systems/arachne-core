use std::{
    collections::BTreeMap,
    sync::{Arc, RwLock},
    time::Duration,
};

use iroh::endpoint::{AfterHandshakeOutcome, BeforeConnectOutcome, EndpointHooks};

use crate::{Error, Node, PeerId, Permissions, Topic};

/// A per-endpoint test link control. Gossip can learn addresses from neighbors,
/// so an address-hint chain alone does not enforce the fixture's network path.
#[derive(Clone, Debug, Default)]
pub(crate) struct BlockedPeer(Arc<RwLock<Option<PeerId>>>);

impl BlockedPeer {
    fn set(&self, peer: Option<PeerId>) {
        *self.0.write().unwrap() = peer;
    }

    fn blocks(&self, peer: PeerId) -> bool {
        *self.0.read().unwrap() == Some(peer)
    }
}

impl EndpointHooks for BlockedPeer {
    async fn before_connect<'a>(
        &'a self,
        remote: &'a iroh::EndpointAddr,
        _alpn: &'a [u8],
    ) -> BeforeConnectOutcome {
        if self.blocks(*remote.id.as_bytes()) {
            BeforeConnectOutcome::Reject
        } else {
            BeforeConnectOutcome::Accept
        }
    }

    async fn after_handshake<'a>(
        &'a self,
        connection: &'a iroh::endpoint::Connection,
    ) -> AfterHandshakeOutcome {
        if self.blocks(*connection.remote_id().as_bytes()) {
            AfterHandshakeOutcome::Reject {
                error_code: 403u32.into(),
                reason: b"test link blocked".to_vec(),
            }
        } else {
            AfterHandshakeOutcome::Accept
        }
    }
}

#[tokio::test]
async fn workspace_publication_crosses_an_intermediate_without_a_direct_route() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let (a, _) = Node::bind_with_identity("127.0.0.1:0".parse().unwrap(), &[71; 32])
            .await
            .unwrap();
        let (b, mut b_received) =
            Node::bind_with_identity("127.0.0.1:0".parse().unwrap(), &[72; 32])
                .await
                .unwrap();
        let (c, mut received) = Node::bind_with_identity("127.0.0.1:0".parse().unwrap(), &[73; 32])
            .await
            .unwrap();
        a.connections.blocked_peer.set(Some(c.id()));
        c.connections.blocked_peer.set(Some(a.id()));
        let workspace = [44; 32];
        let topic = Topic::new("streams/opaque").unwrap();
        let offline = *iroh::SecretKey::from_bytes(&[74; 32]).public().as_bytes();
        let policy = BTreeMap::from([
            (a.id(), Permissions::AllTopics),
            (b.id(), Permissions::AllTopics),
            (c.id(), Permissions::AllTopics),
            (offline, Permissions::AllTopics),
        ]);
        for node in [&a, &b, &c] {
            node.install_verified_policy(workspace, 1, policy.clone())
                .await
                .unwrap();
        }

        // A and C initially know only B. The test-only Iroh hooks also block
        // their direct link after Gossip learns the other endpoint's address.
        a.add_address_hint(b.id(), b.address()).await.unwrap();
        b.add_address_hint(a.id(), a.address()).await.unwrap();
        b.add_address_hint(c.id(), c.address()).await.unwrap();
        c.add_address_hint(b.id(), b.address()).await.unwrap();
        assert!(a.address_hint(c.id()).await.is_none());
        assert!(c.address_hint(a.id()).await.is_none());

        let interest = c.subscribe(workspace, 1, topic.clone()).await.unwrap();
        assert!(interest.admitted.contains(&c.id()));
        assert!(interest.failed.iter().any(|(peer, _)| *peer == a.id()));

        b.enable_gossip(workspace, 1, &workspace).await.unwrap();
        a.enable_gossip(workspace, 1, &workspace).await.unwrap();
        c.enable_gossip(workspace, 1, &workspace).await.unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let neighbors = c.live_neighbors(workspace).await;
            if neighbors.contains(&b.id()) {
                assert!(!neighbors.contains(&a.id()));
                break;
            }
            assert!(tokio::time::Instant::now() < deadline);
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let report = a
            .publish(workspace, 1, topic.clone(), b"via-b".to_vec())
            .await
            .unwrap();
        assert!(report.queued);
        assert!(report.admitted.is_empty());
        assert!(report.failed.is_empty());

        let message = tokio::time::timeout(Duration::from_secs(5), received.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(message.sender, a.id());
        assert_eq!(message.received_from, b.id());
        assert_eq!(message.workspace, workspace);
        assert_eq!(message.topic, topic);
        assert_eq!(message.payload, b"via-b");
        assert!(
            b_received.try_recv().is_err(),
            "an unsubscribed forwarder exposed an application event"
        );
        a.publish(workspace, 1, topic.clone(), b"via-b".to_vec())
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(received.try_recv().is_err());

        // A full application queue at the forwarding peer must not stall a
        // healthy subscriber. Fill B locally on a separate topic, then make B
        // interested in the forwarded topic without draining its receiver.
        let slow_topic = Topic::new("streams/slow-consumer").unwrap();
        b.subscribe(workspace, 1, slow_topic.clone()).await.unwrap();
        for sequence in 0_u16..256 {
            b.publish(
                workspace,
                1,
                slow_topic.clone(),
                sequence.to_be_bytes().to_vec(),
            )
            .await
            .unwrap();
        }
        b.subscribe(workspace, 1, topic.clone()).await.unwrap();
        a.publish(
            workspace,
            1,
            topic.clone(),
            b"healthy-after-slow-peer".to_vec(),
        )
        .await
        .unwrap();
        let healthy = tokio::time::timeout(Duration::from_secs(2), received.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(healthy.payload, b"healthy-after-slow-peer");

        // Knowing the workspace identifier and inventing a local policy does not
        // let an endpoint enter another member's overlay.
        let (outsider, _) = Node::bind_with_identity("127.0.0.1:0".parse().unwrap(), &[75; 32])
            .await
            .unwrap();
        outsider
            .install_verified_policy(
                workspace,
                1,
                BTreeMap::from([
                    (outsider.id(), Permissions::AllTopics),
                    (b.id(), Permissions::AllTopics),
                ]),
            )
            .await
            .unwrap();
        outsider
            .add_address_hint(b.id(), b.address())
            .await
            .unwrap();
        outsider
            .enable_gossip(workspace, 1, &workspace)
            .await
            .unwrap();
        assert!(matches!(
            outsider
                .publish(workspace, 1, topic.clone(), b"denied".to_vec())
                .await,
            Err(Error::MissingPeer)
        ));
        assert!(received.try_recv().is_err());
        outsider.close().await;

        // Losing the forwarding neighbor must repair to another authorized path.
        b.close().await;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while !a.live_neighbors(workspace).await.is_empty()
            || !c.live_neighbors(workspace).await.is_empty()
        {
            assert!(
                tokio::time::Instant::now() < deadline,
                "forwarding link did not close"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let disconnected = a
            .publish(
                workspace,
                1,
                topic.clone(),
                b"before-route-refresh".to_vec(),
            )
            .await;
        assert!(matches!(disconnected, Err(Error::MissingPeer)));
        assert!(received.try_recv().is_err());
        a.connections.blocked_peer.set(None);
        c.connections.blocked_peer.set(None);
        a.add_address_hint(c.id(), c.address()).await.unwrap();
        c.add_address_hint(a.id(), a.address()).await.unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            match a
                .publish(workspace, 1, topic.clone(), b"after-loss".to_vec())
                .await
            {
                Ok(report) if report.queued => break,
                Err(Error::MissingPeer) if tokio::time::Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                result => panic!("overlay did not repair after neighbor loss: {result:?}"),
            }
        }
        let repaired = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let message = received.recv().await.unwrap();
                if message.payload == b"after-loss" {
                    break message;
                }
                assert_eq!(message.payload, b"before-route-refresh");
            }
        })
        .await
        .unwrap();
        assert_eq!(repaired.sender, a.id());
        assert_eq!(repaired.received_from, a.id());
        assert_eq!(repaired.payload, b"after-loss");

        let current = BTreeMap::from([
            (a.id(), Permissions::AllTopics),
            (c.id(), Permissions::AllTopics),
        ]);
        for node in [&a, &c] {
            node.install_verified_policy(workspace, 2, current.clone())
                .await
                .unwrap();
        }
        let (removed, _) = Node::bind_with_identity("127.0.0.1:0".parse().unwrap(), &[72; 32])
            .await
            .unwrap();
        removed
            .install_verified_policy(
                workspace,
                1,
                BTreeMap::from([
                    (removed.id(), Permissions::AllTopics),
                    (c.id(), Permissions::AllTopics),
                ]),
            )
            .await
            .unwrap();
        removed.add_address_hint(c.id(), c.address()).await.unwrap();
        removed
            .enable_gossip(workspace, 1, &workspace)
            .await
            .unwrap();
        assert!(matches!(
            removed
                .publish(workspace, 1, topic.clone(), b"stale-member".to_vec())
                .await,
            Err(Error::MissingPeer)
        ));
        assert!(received.try_recv().is_err());
        removed.close().await;

        let report = a
            .publish(workspace, 2, topic.clone(), b"current-policy".to_vec())
            .await
            .unwrap();
        assert!(report.queued);
        let current = tokio::time::timeout(Duration::from_secs(5), received.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(current.payload, b"current-policy");
        assert_eq!(current.sender, a.id());

        a.close().await;
        c.close().await;
    })
    .await
    .unwrap();
}
