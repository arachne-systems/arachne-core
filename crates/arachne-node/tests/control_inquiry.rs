use arachne_node::Node;
use std::sync::Arc;
use std::time::Duration;

async fn pair() -> (Node, Node) {
    let (client, _) = Node::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let (server, _) = Node::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    client
        .add_address_hint(server.id(), server.address())
        .await
        .unwrap();
    (client, server)
}

#[tokio::test]
async fn an_inquiry_is_answered_while_the_host_never_polls() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (client, mut server) = pair().await;
        let asker = client.id();
        server.set_inquiry_responder(Arc::new(move |peer, payload| {
            assert_eq!(peer, asker, "the responder sees the authenticated peer");
            payload
                .starts_with(b"R")
                .then(|| [b"read:".as_slice(), payload].concat())
        }));
        // Nobody calls poll_control: the reply cannot come from the host.
        let reply = client.request_control(server.id(), b"R1").await.unwrap();
        assert_eq!(reply, b"read:R1");
        assert!(server.poll_control().is_none(), "an inquiry must not reach the host queue");
        let timing = server.control_timing();
        assert_eq!(timing.inquiry.count, 1);
        assert_eq!(timing.host_wait.count, 0);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn a_request_the_responder_declines_goes_to_the_host_and_is_timed() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (client, mut server) = pair().await;
        server.set_inquiry_responder(Arc::new(|_, payload| payload.starts_with(b"R").then(Vec::new)));
        let send = tokio::spawn(client.request_control(server.id(), b"W1"));
        server.control_signal().notified().await;
        // The host is slow to look: that time is queue wait, not service.
        tokio::time::sleep(Duration::from_millis(60)).await;
        let request = server.poll_control().expect("a write reaches the host");
        assert_eq!(request.payload(), b"W1");
        request.respond(b"done".to_vec()).unwrap();
        assert_eq!(send.await.unwrap().unwrap(), b"done");
        let timing = server.control_timing();
        assert_eq!(timing.inquiry.count, 0);
        assert_eq!(timing.host_wait.count, 1);
        assert_eq!(timing.host_service.count, 1);
        assert!(timing.host_wait.max_us >= 60_000, "{timing:?}");
        assert!(timing.host_service.max_us < 60_000, "{timing:?}");
    })
    .await
    .unwrap();
}
