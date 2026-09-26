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
async fn three_peers_deliver_a_critical_reply_after_a_stream_burst() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let mut nodes = Vec::new();
        let mut messages = Vec::new();
        for _ in 0..3 {
            let (node, receiver) = Node::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
            nodes.push(node);
            messages.push(receiver);
        }
        let workspace = [48; 32];
        let topic = Topic::new("shared/stream").unwrap();
        let policy: BTreeMap<_, _> = nodes
            .iter()
            .map(|node| (node.id(), access(&topic)))
            .collect();
        for node in &nodes {
            node.install_verified_policy(workspace, 1, policy.clone())
                .await
                .unwrap();
            for peer in &nodes {
                if node.id() != peer.id() {
                    node.add_address_hint(peer.id(), peer.address())
                        .await
                        .unwrap();
                }
            }
        }
        for node in &nodes {
            node.subscribe(workspace, 1, topic.clone()).await.unwrap();
        }
        for left in 0..3 {
            for right in left + 1..3 {
                let (dialer, listener) = if nodes[left].id() < nodes[right].id() {
                    (&nodes[left], &nodes[right])
                } else {
                    (&nodes[right], &nodes[left])
                };
                listener
                    .enable_moq_delivery(workspace, 1, dialer.id(), topic.clone())
                    .await
                    .unwrap();
                dialer
                    .enable_moq_delivery(workspace, 1, listener.id(), topic.clone())
                    .await
                    .unwrap();
            }
        }
        while nodes
            .iter()
            .any(|node| node.moq_metrics().sessions_active != 2)
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        for sequence in 1..=15 {
            nodes[0]
                .publish_protected_with_class(
                    workspace,
                    1,
                    topic.clone(),
                    sequence,
                    DeliveryClass::Critical,
                    vec![sequence as u8],
                )
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        // A follower requests a reply after the first publisher ends its burst.
        nodes[1]
            .publish_protected_with_class(
                workspace,
                1,
                topic.clone(),
                1,
                DeliveryClass::Critical,
                b"request".to_vec(),
            )
            .await
            .unwrap();
        loop {
            if let Ok(message) = messages[0].try_recv()
                && message.payload == b"request"
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        for sequence in [16, 17] {
            nodes[0]
                .publish_protected_with_class(
                    workspace,
                    1,
                    topic.clone(),
                    sequence,
                    DeliveryClass::Critical,
                    vec![sequence as u8],
                )
                .await
                .unwrap();
        }
        for receiver in messages.iter_mut().skip(1) {
            let mut replies = BTreeSet::new();
            while replies.len() != 2 {
                if let Ok(message) = receiver.try_recv() {
                    if matches!(message.payload.as_slice(), [16] | [17]) {
                        replies.insert(message.payload[0]);
                    }
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
        for node in nodes {
            node.close().await;
        }
    })
    .await
    .expect("critical reply was lost after the stream burst");
}

#[tokio::test]
async fn dialer_reconnects_after_the_listener_restarts_on_the_same_port() {
    tokio::time::timeout(Duration::from_secs(45), async {
        let dialer_secret = [71; 32];
        let listener_secret = [72; 32];
        let dialer_address = unused_address();
        let listener_address = unused_address();
        let (node_a, node_a_messages) = Node::bind_with_identity(dialer_address, &dialer_secret)
            .await
            .unwrap();
        let (node_b, node_b_messages) =
            Node::bind_with_identity(listener_address, &listener_secret)
                .await
                .unwrap();
        let (
            dialer,
            mut dialer_messages,
            listener,
            _listener_messages,
            listener_secret,
            listener_address,
        ) = if node_a.id() < node_b.id() {
            (
                node_a,
                node_a_messages,
                node_b,
                node_b_messages,
                listener_secret,
                listener_address,
            )
        } else {
            (
                node_b,
                node_b_messages,
                node_a,
                node_a_messages,
                dialer_secret,
                dialer_address,
            )
        };
        let topic = Topic::new("ptt/audio").unwrap();
        let workspace = [45; 32];
        let policy = BTreeMap::from([
            (dialer.id(), access(&topic)),
            (listener.id(), access(&topic)),
        ]);
        dialer
            .add_address_hint(listener.id(), listener.address())
            .await
            .unwrap();
        listener
            .add_address_hint(dialer.id(), dialer.address())
            .await
            .unwrap();
        dialer
            .install_verified_policy(workspace, 1, policy.clone())
            .await
            .unwrap();
        listener
            .install_verified_policy(workspace, 1, policy.clone())
            .await
            .unwrap();
        dialer.subscribe(workspace, 1, topic.clone()).await.unwrap();
        listener
            .subscribe(workspace, 1, topic.clone())
            .await
            .unwrap();
        listener
            .enable_moq_delivery(workspace, 1, dialer.id(), topic.clone())
            .await
            .unwrap();
        dialer
            .enable_moq_delivery(workspace, 1, listener.id(), topic.clone())
            .await
            .unwrap();
        wait_for_sessions(&dialer, &listener, 1).await;

        listener.close().await;
        let (listener, mut listener_messages) =
            Node::bind_with_identity(listener_address, &listener_secret)
                .await
                .unwrap();
        dialer
            .add_address_hint(listener.id(), listener.address())
            .await
            .unwrap();
        listener
            .add_address_hint(dialer.id(), dialer.address())
            .await
            .unwrap();
        listener
            .install_verified_policy(workspace, 1, policy)
            .await
            .unwrap();
        listener
            .subscribe(workspace, 1, topic.clone())
            .await
            .unwrap();
        listener
            .enable_moq_delivery(workspace, 1, dialer.id(), topic.clone())
            .await
            .unwrap();

        wait_for_sessions(&dialer, &listener, 1).await;
        let frame = b"packet after listener restart".to_vec();
        let report = dialer
            .publish_protected_with_class(
                workspace,
                1,
                topic.clone(),
                1,
                DeliveryClass::Critical,
                frame.clone(),
            )
            .await
            .unwrap();
        assert!(report.queued, "{report:?}");
        assert!(report.failed.is_empty(), "{report:?}");
        let received = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Ok(message) = listener_messages.try_recv()
                    && message.payload == frame
                {
                    break message;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(received.received_from, dialer.id());

        let reverse_frame = b"packet in reverse after listener restart".to_vec();
        let report = listener
            .publish_protected_with_class(
                workspace,
                1,
                topic,
                1,
                DeliveryClass::Critical,
                reverse_frame.clone(),
            )
            .await
            .unwrap();
        assert!(report.queued, "{report:?}");
        assert!(report.failed.is_empty(), "{report:?}");
        let reverse_received = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Ok(message) = dialer_messages.try_recv()
                    && message.payload == reverse_frame
                {
                    break message;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(reverse_received.received_from, listener.id());

        dialer.close().await;
        listener.close().await;
    })
    .await
    .unwrap();
}

fn unused_address() -> std::net::SocketAddr {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.local_addr().unwrap()
}

async fn wait_for_sessions(left: &Node, right: &Node, expected: usize) {
    for _ in 0..500 {
        if left.moq_metrics().sessions_active == expected
            && right.moq_metrics().sessions_active == expected
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(left.moq_metrics().sessions_active, expected);
    assert_eq!(right.moq_metrics().sessions_active, expected);
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

        // Both endpoints opt in; either can restore a connection after restart.
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

        // A new revision with unchanged members must replace the old MoQ scope.
        let next_policy = BTreeMap::from([
            (sender.id(), access(&topic)), (receiver.id(), access(&topic)),
        ]);
        receiver.install_verified_policy(workspace, 2, next_policy.clone()).await.unwrap();
        sender.install_verified_policy(workspace, 2, next_policy).await.unwrap();
        receiver.enable_moq_delivery(workspace, 2, sender.id(), topic.clone()).await.unwrap();
        sender.enable_moq_delivery(workspace, 2, receiver.id(), topic.clone()).await.unwrap();

        // A policy revision and peer removal close both ends of the old session.
        receiver
            .install_verified_policy(
                workspace,
                3,
                BTreeMap::from([(receiver.id(), Permissions::AllTopics)]),
            )
            .await
            .unwrap();
        sender
            .install_verified_policy(
                workspace,
                3,
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

#[tokio::test]
async fn enabled_stream_keeps_recent_publications_until_interest_arrives() {
    tokio::time::timeout(Duration::from_secs(12), async {
        let (sender, _) = Node::bind_with_identity(unused_address(), &[83; 32])
            .await
            .unwrap();
        let (receiver, mut incoming) = Node::bind_with_identity(unused_address(), &[84; 32])
            .await
            .unwrap();
        let workspace = [48; 32];
        let topic = Topic::new("streams/example").unwrap();
        let policy = BTreeMap::from([
            (sender.id(), access(&topic)),
            (receiver.id(), access(&topic)),
        ]);
        sender
            .install_verified_policy(workspace, 1, policy.clone())
            .await
            .unwrap();
        receiver
            .install_verified_policy(workspace, 1, policy)
            .await
            .unwrap();
        sender
            .add_address_hint(receiver.id(), receiver.address())
            .await
            .unwrap();
        receiver
            .add_address_hint(sender.id(), sender.address())
            .await
            .unwrap();
        sender
            .enable_moq_delivery(workspace, 1, receiver.id(), topic.clone())
            .await
            .unwrap();
        // A restored reader can be authorized before its interest reaches the publisher.
        for sequence in 1..=3 {
            sender
                .publish_protected_with_class(
                    workspace,
                    1,
                    topic.clone(),
                    sequence,
                    DeliveryClass::Critical,
                    vec![sequence as u8],
                )
                .await
                .unwrap();
        }
        for sequence in 4..=6 {
            sender
                .publish_protected_to_with_class(
                    workspace,
                    1,
                    topic.clone(),
                    sequence,
                    vec![receiver.id()],
                    vec![[1; 32]],
                    DeliveryClass::Critical,
                    vec![sequence as u8],
                )
                .await
                .unwrap();
        }
        assert!(
            sender
                .publish_protected_with_class(
                    workspace,
                    1,
                    topic.clone(),
                    7,
                    DeliveryClass::Critical,
                    vec![0; 16 * 1024 + 1]
                )
                .await
                .is_err()
        );
        assert!(
            sender
                .publish_protected_to_with_class(
                    workspace,
                    1,
                    topic.clone(),
                    7,
                    vec![receiver.id()],
                    vec![],
                    DeliveryClass::Critical,
                    vec![7]
                )
                .await
                .is_err()
        );
        assert_eq!(sender.moq_metrics().packets_sent, 6);
        receiver
            .subscribe(workspace, 1, topic.clone())
            .await
            .unwrap();
        receiver
            .enable_moq_delivery(workspace, 1, sender.id(), topic.clone())
            .await
            .unwrap();
        wait_for_sessions(&sender, &receiver, 1).await;
        let mut received = BTreeSet::new();
        while received.len() < 6 {
            if let Ok(message) = incoming.try_recv() {
                received.insert(message.payload);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(received, (1..=6).map(|value| vec![value]).collect());
        sender.close().await;
        receiver.close().await;
    })
    .await
    .expect("an enabled stream dropped its prefix before the reader subscribed");
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
