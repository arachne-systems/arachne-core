use arachne_node::Node;
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

const CONTROL: &[u8] = b"data-fabric/control/1";

#[tokio::test]
async fn stalled_frame_times_out_without_closing_other_exchanges() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (node, _) = Node::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let peer = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .clear_relay_transports()
            .clear_ip_transports()
            .bind_addr("127.0.0.1:0")
            .unwrap()
            .bind()
            .await
            .unwrap();
        let connection = peer
            .connect(
                iroh::EndpointAddr::new(iroh::PublicKey::from_bytes(&node.id()).unwrap())
                    .with_ip_addr(node.address()),
                b"data-fabric/pubsub-experiment/1",
            )
            .await
            .unwrap();
        let (mut stalled, mut response) = connection.open_bi().await.unwrap();
        stalled.write_all(&[0, 1]).await.unwrap(); // No EOF: expires at the data deadline.
        let rejected_frame = async {
            let (mut send, mut recv) = connection.open_bi().await.unwrap();
            send.write_all(&[0, 255]).await.unwrap(); // Deliberately invalid frame.
            send.finish().unwrap();
            assert_eq!(recv.read_to_end(1).await.unwrap(), [0]);
        };
        tokio::time::timeout(Duration::from_secs(2), rejected_frame)
            .await
            .unwrap();
        assert!(
            response.read_to_end(1).await.is_err(),
            "timeout is not an empty reply"
        );
        assert!(connection.close_reason().is_none());
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        send.write_all(&[0, 255]).await.unwrap();
        send.finish().unwrap();
        assert_eq!(recv.read_to_end(1).await.unwrap(), [0]);
        node.close().await;
        peer.close().await;
    })
    .await
    .unwrap();
}

async fn next_request(node: &mut Node) -> arachne_node::ControlRequest {
    loop {
        if let Some(request) = node.poll_control() {
            return request;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

#[tokio::test]
async fn cancellation_is_stream_scoped_and_requests_survive_peer_restart() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let (sender, _) = Node::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        // Fixture only: a restarted authenticated peer has the same identity.
        let seed = [45; 32];
        let (mut receiver, _) = Node::bind_with_identity("127.0.0.1:0".parse().unwrap(), &seed)
            .await
            .unwrap();
        let peer = receiver.id();
        sender
            .add_address_hint(peer, receiver.address())
            .await
            .unwrap();
        let cancelled = tokio::spawn(sender.request_control(peer, b"cancel"));
        let request = next_request(&mut receiver).await;
        assert_eq!(request.payload(), b"cancel");
        let retained = tokio::spawn(sender.request_control(peer, b"keep"));
        let retained_request = next_request(&mut receiver).await;
        // Two active exchanges, one path: this also tests the Node receiver's
        // multiplexing instead of only a raw QUIC test server.
        assert_eq!(sender.transport_metrics().paths.len(), 1);
        cancelled.abort();
        assert!(cancelled.await.unwrap_err().is_cancelled());
        while !request.expired() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(request.respond(b"too late".to_vec()).is_err());
        retained_request.respond(b"kept".to_vec()).unwrap();
        assert_eq!(retained.await.unwrap().unwrap(), b"kept");
        for _ in 0..3 {
            let send = tokio::spawn(sender.request_control(peer, b"again"));
            next_request(&mut receiver)
                .await
                .respond(b"ok".to_vec())
                .unwrap();
            assert_eq!(send.await.unwrap().unwrap(), b"ok");
            assert_eq!(sender.transport_metrics().paths.len(), 1);
        }
        receiver.close().await;
        while !sender.transport_metrics().paths.is_empty() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let (mut restarted, _) = Node::bind_with_identity("127.0.0.1:0".parse().unwrap(), &seed)
            .await
            .unwrap();
        sender
            .add_address_hint(peer, restarted.address())
            .await
            .unwrap();
        let send = tokio::spawn(sender.request_control(peer, b"fresh"));
        let request = next_request(&mut restarted).await;
        assert_eq!(
            request.payload(),
            b"fresh",
            "cancelled/completed requests must not replay"
        );
        request.respond(b"reconnected".to_vec()).unwrap();
        assert_eq!(send.await.unwrap().unwrap(), b"reconnected");
        assert!(restarted.poll_control().is_none());
        sender.close().await;
        restarted.close().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn late_reply_after_caller_timeout_does_not_poison_reused_connection() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (sender, _) = Node::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let (mut receiver, _) = Node::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        sender
            .add_address_hint(receiver.id(), receiver.address())
            .await
            .unwrap();

        let mut first = tokio::spawn(sender.request_control(receiver.id(), b"late-admission"));
        let request = next_request(&mut receiver).await;
        assert!(tokio::time::timeout(Duration::from_millis(25), &mut first)
            .await
            .is_err());
        first.abort();
        assert!(first.await.unwrap_err().is_cancelled());

        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(request.respond(b"too late".to_vec()).is_err());

        let second = tokio::spawn(sender.request_control(receiver.id(), b"retry-admission"));
        next_request(&mut receiver)
            .await
            .respond(b"retry-ok".to_vec())
            .unwrap();
        assert_eq!(second.await.unwrap().unwrap(), b"retry-ok");

        sender.close().await;
        receiver.close().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn idle_connection_expires_and_the_next_exchange_reconnects() {
    tokio::time::timeout(Duration::from_secs(70), async {
        let (sender, _) = Node::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let (mut receiver, _) = Node::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        sender
            .add_address_hint(receiver.id(), receiver.address())
            .await
            .unwrap();
        let send = tokio::spawn(sender.request_control(receiver.id(), b"before idle"));
        next_request(&mut receiver)
            .await
            .respond(b"ok".to_vec())
            .unwrap();
        assert_eq!(send.await.unwrap().unwrap(), b"ok");
        assert!(!sender.transport_metrics().paths.is_empty());
        while !sender.transport_metrics().paths.is_empty() {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let send = tokio::spawn(sender.request_control(receiver.id(), b"after idle"));
        next_request(&mut receiver)
            .await
            .respond(b"fresh".to_vec())
            .unwrap();
        assert_eq!(send.await.unwrap().unwrap(), b"fresh");
        sender.close().await;
        receiver.close().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn repeated_and_overlapping_control_requests_reuse_one_connection() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let (node, _) = Node::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let peer = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .clear_relay_transports()
            .clear_ip_transports()
            .bind_addr("127.0.0.1:0")
            .unwrap()
            .alpns(vec![CONTROL.to_vec()])
            .bind()
            .await
            .unwrap();
        let id = *peer.id().as_bytes();
        node.add_address_hint(id, peer.bound_sockets()[0])
            .await
            .unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let count = accepted.clone();
        let endpoint = peer.clone();
        let server = tokio::spawn(async move {
            let mut workers = tokio::task::JoinSet::new();
            while let Some(incoming) = endpoint.accept().await {
                count.fetch_add(1, Ordering::Relaxed);
                workers.spawn(async move {
                    let connection = incoming.await.unwrap();
                    while let Ok((mut send, mut recv)) = connection.accept_bi().await {
                        let bytes = recv.read_to_end(1024).await.unwrap();
                        send.write_all(&bytes).await.unwrap();
                        send.finish().unwrap();
                    }
                });
            }
            while let Some(result) = workers.join_next().await {
                result.unwrap();
            }
        });
        let before = node.transport_metrics();
        for i in 0..20 {
            assert_eq!(node.request_control(id, &[i; 128]).await.unwrap(), [i; 128]);
        }
        let mut overlapping = tokio::task::JoinSet::new();
        for i in 20..24 {
            overlapping.spawn(node.request_control(id, &[i; 128]));
        }
        let mut replies = Vec::new();
        while let Some(reply) = overlapping.join_next().await {
            replies.push(reply.unwrap().unwrap());
        }
        replies.sort();
        assert_eq!(replies, (20..24).map(|i| vec![i; 128]).collect::<Vec<_>>());
        let after = node.transport_metrics();
        let handshakes = accepted.load(Ordering::Relaxed);
        eprintln!(
            "24 control exchanges: connections={handshakes} sent={} received={}",
            after.sent_bytes - before.sent_bytes,
            after.received_bytes - before.received_bytes
        );
        node.close().await;
        peer.close().await;
        server.await.unwrap();
        assert_eq!(
            handshakes, 1,
            "every request must not pay for a new handshake"
        );
    })
    .await
    .unwrap();
}
