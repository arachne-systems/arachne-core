#![cfg(feature = "moq")]

use arachne_node::{DeliveryClass, Node, Permissions, Topic};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};

fn access(topic: &Topic) -> Permissions {
    Permissions::Selected {
        publish: BTreeSet::from([topic.clone()]),
        subscribe: BTreeSet::from([topic.clone()]),
    }
}

#[tokio::test]
async fn opted_in_peers_exchange_packets_over_moq_and_reject_an_outsider() {
    tokio::time::timeout(Duration::from_secs(35), async {
        let (left, mut left_messages) = Node::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let (right, mut right_messages) = Node::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let topic = Topic::new("ptt/audio").unwrap();
        let workspace = [44; 32];
        let policy = BTreeMap::from([
            (left.id(), access(&topic)),
            (right.id(), access(&topic)),
        ]);
        left.add_address_hint(right.id(), right.address()).await.unwrap();
        right.add_address_hint(left.id(), left.address()).await.unwrap();
        left.install_verified_policy(workspace, 1, policy.clone())
            .await
            .unwrap();
        right
            .install_verified_policy(workspace, 1, policy)
            .await
            .unwrap();
        left.subscribe(workspace, 1, topic.clone()).await.unwrap();
        right.subscribe(workspace, 1, topic.clone()).await.unwrap();

        // The higher endpoint listens first; the lower endpoint is the only dialer.
        let (sender, sender_messages, receiver, receiver_messages) =
            if left.id() < right.id() {
                (&left, &mut left_messages, &right, &mut right_messages)
            } else {
                (&right, &mut right_messages, &left, &mut left_messages)
            };
        receiver
            .enable_moq_delivery(workspace, 1, sender.id(), topic.clone())
            .await
            .unwrap();
        sender
            .enable_moq_delivery(workspace, 1, receiver.id(), topic.clone())
            .await
            .unwrap();

        for _ in 0..400 {
            if sender.moq_metrics().sessions_active == 1
                && receiver.moq_metrics().sessions_active == 1
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(sender.moq_metrics().sessions_active, 1);
        assert_eq!(receiver.moq_metrics().sessions_active, 1);

        let first = b"opaque protected packet from the dialer".to_vec();
        let report = sender
            .publish_protected_with_class(
                workspace,
                1,
                topic.clone(),
                7,
                DeliveryClass::Critical,
                first.clone(),
            )
            .await
            .unwrap();
        assert!(report.queued, "MoQ admission is local queueing, not a receipt");
        assert_eq!(report.failed.len(), 0);
        let received = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Ok(message) = receiver_messages.try_recv()
                    && message.sender == sender.id()
                    && message.payload == first
                {
                    break message;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(received.received_from, sender.id());

        let second = b"opaque protected packet from the listener".to_vec();
        let report = receiver
            .publish_protected_with_class(
                workspace,
                1,
                topic.clone(),
                11,
                DeliveryClass::Critical,
                second.clone(),
            )
            .await
            .unwrap();
        assert!(report.queued);
        assert_eq!(report.failed.len(), 0);
        let received = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Ok(message) = sender_messages.try_recv()
                    && message.sender == receiver.id()
                    && message.payload == second
                {
                    break message;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(received.received_from, receiver.id());

        // An authenticated Iroh endpoint without an enabled peer route is refused
        // before a MoQ session can subscribe to the scoped origin.
        let address = iroh::EndpointAddr::new(
            iroh::PublicKey::from_bytes(&receiver.id()).unwrap(),
        )
        .with_ip_addr(receiver.address());
        let outsider_result = outsider_moq_connect(address, workspace, receiver.id()).await;
        assert!(outsider_result);
        assert!(receiver.moq_metrics().rejected_sessions >= 1);

        let send_metrics = sender.moq_metrics();
        let receive_metrics = receiver.moq_metrics();
        assert_eq!(send_metrics.packets_sent, 1);
        assert_eq!(receive_metrics.packets_received, 1);
        assert_eq!(send_metrics.sessions_total, 1);
        assert_eq!(receive_metrics.sessions_total, 1);
        println!(
            "P2_MOQ_RECEIPT {{\"data_path\":\"moq\",\"sender\":{},\"receiver\":{},\"sender_metrics\":{},\"receiver_metrics\":{}}}",
            serde_json::to_string(&sender.id()).unwrap(),
            serde_json::to_string(&receiver.id()).unwrap(),
            serde_json::to_string(&send_metrics).unwrap(),
            serde_json::to_string(&receive_metrics).unwrap(),
        );

        // A policy revision and peer removal close both ends of the old session.
        receiver
            .install_verified_policy(
                workspace,
                2,
                BTreeMap::from([(receiver.id(), Permissions::AllTopics)]),
            )
            .await
            .unwrap();
        sender
            .install_verified_policy(
                workspace,
                2,
                BTreeMap::from([(sender.id(), Permissions::AllTopics)]),
            )
            .await
            .unwrap();
        for _ in 0..200 {
            if sender.moq_metrics().sessions_active == 0
                && receiver.moq_metrics().sessions_active == 0
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(sender.moq_metrics().sessions_active, 0);
        assert_eq!(receiver.moq_metrics().sessions_active, 0);

        left.close().await;
        right.close().await;
    })
    .await
    .unwrap();
}

async fn outsider_moq_connect(
    address: iroh::EndpointAddr,
    workspace: [u8; 32],
    publisher: [u8; 32],
) -> bool {
    // Use a peer endpoint configured with the pinned MoQ ALPN set. The target
    // uses its normal accept loop and denies the unknown authenticated peer.
    let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .clear_relay_transports()
        .clear_ip_transports()
        .alpns(
            iroh_moq::alpns()
                .into_iter()
                .map(|alpn| alpn.to_vec())
                .collect(),
        )
        .bind_addr("127.0.0.1:0")
        .unwrap()
        .bind()
        .await
        .unwrap();
    let moq = iroh_moq::Moq::new(endpoint.clone());
    let result = tokio::time::timeout(Duration::from_secs(8), moq.connect(address)).await;
    let rejected_before_origin = match result {
        Ok(Err(_)) | Err(_) => true,
        Ok(Ok(session)) => {
            let path = format!(
                "workspace/{}/author/{}/epoch/1",
                hex(&workspace),
                hex(&publisher)
            );
            !matches!(
                tokio::time::timeout(Duration::from_secs(2), session.subscribe(path.as_str()))
                    .await,
                Ok(Ok(_))
            )
        }
    };
    moq.shutdown().await;
    endpoint.close().await;
    rejected_before_origin
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
