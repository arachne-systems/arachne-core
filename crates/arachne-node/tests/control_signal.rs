use arachne_node::Node;
use std::time::Duration;

#[tokio::test]
async fn control_arrival_wakes_a_parked_waiter() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (client, _) = Node::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let (mut server, _) = Node::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        client
            .add_address_hint(server.id(), server.address())
            .await
            .unwrap();
        let signal = server.control_signal();
        let send = tokio::spawn(client.request_control(server.id(), b"wake"));
        signal.notified().await;
        let request = server
            .poll_control()
            .expect("the signal must fire after the request is queued");
        assert_eq!(request.payload(), b"wake");
        request.respond(b"ok".to_vec()).unwrap();
        assert_eq!(send.await.unwrap().unwrap(), b"ok");
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn closing_a_session_cancels_an_unanswered_control_exchange() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (client, _) = Node::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let (server, _) = Node::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        client.add_address_hint(server.id(), server.address()).await.unwrap();
        let cancel = client.control_cancellation();
        let pending = tokio::spawn(client.request_control(server.id(), b"hold"));
        server.control_signal().notified().await;
        cancel.send_replace(true);
        assert!(matches!(pending.await.unwrap(), Err(arachne_node::Error::Cancelled)));
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn a_signal_raised_before_the_wait_is_kept() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (client, _) = Node::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let (mut server, _) = Node::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        client
            .add_address_hint(server.id(), server.address())
            .await
            .unwrap();
        let signal = server.control_signal();
        let send = tokio::spawn(client.request_control(server.id(), b"early"));
        // Nobody is waiting yet. The permit must be stored, not dropped.
        tokio::time::sleep(Duration::from_millis(300)).await;
        tokio::time::timeout(Duration::from_secs(1), signal.notified())
            .await
            .expect("a signal raised with no waiter was lost");
        server.poll_control().unwrap().respond(vec![1]).unwrap();
        send.await.unwrap().unwrap();
    })
    .await
    .unwrap();
}

/// Requests set aside by `poll_control_matching` are reported as waiting, and
/// `rearm_control_signal` wakes the host for them; their arrival signal was
/// already spent when they were set aside.
#[tokio::test]
async fn set_aside_requests_are_reported_and_rearm_wakes_the_host() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (client, _) = Node::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let (mut server, _) = Node::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        client.add_address_hint(server.id(), server.address()).await.unwrap();
        let signal = server.control_signal();
        let other = tokio::spawn(client.request_control(server.id(), b"other"));
        signal.notified().await;
        let wanted = tokio::spawn(client.request_control(server.id(), b"wanted"));
        signal.notified().await;
        assert!(!server.has_deferred_controls());
        let taken = server
            .poll_control_matching(|payload| payload == b"wanted")
            .expect("the matching request is taken");
        assert_eq!(taken.payload(), b"wanted");
        assert!(server.has_deferred_controls(), "the other request must be reported as set aside");
        taken.respond(vec![1]).unwrap();
        wanted.await.unwrap().unwrap();
        // Both arrival permits are spent: nothing wakes the host but a rearm.
        assert!(tokio::time::timeout(Duration::from_millis(100), signal.notified()).await.is_err());
        server.rearm_control_signal();
        tokio::time::timeout(Duration::from_secs(1), signal.notified())
            .await
            .expect("rearm did not wake the host");
        let request = server.poll_control().expect("the set-aside request is still there");
        assert_eq!(request.payload(), b"other");
        assert!(!server.has_deferred_controls());
        request.respond(vec![2]).unwrap();
        other.await.unwrap().unwrap();
    })
    .await
    .unwrap();
}

/// A short request that must not wait is found behind a long queue in one
/// scan, and the rest keep their order. On tablets a membership range pull
/// waited behind 100+ profile-page queries from 50 joiners in the owner's one
/// control queue and timed out (JOSA and BIG RED, fix16, 2026-09-19).
#[tokio::test]
async fn an_urgent_request_is_found_behind_a_long_queue_in_one_scan() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let (client, _) = Node::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let (mut server, _) = Node::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        client.add_address_hint(server.id(), server.address()).await.unwrap();
        let signal = server.control_signal();
        let mut queued = Vec::new();
        for index in 0..20u8 {
            queued.push(tokio::spawn(client.request_control(server.id(), &[b'q', index])));
            signal.notified().await;
        }
        let urgent = tokio::spawn(client.request_control(server.id(), b"urgent"));
        signal.notified().await;
        let taken = server
            .poll_control_first(|payload| payload == b"urgent", 64)
            .expect("the urgent request is found behind 20 others");
        assert!(taken.waited() < Duration::from_secs(5));
        taken.respond(vec![1]).unwrap();
        urgent.await.unwrap().unwrap();
        for index in 0..20u8 {
            let request = server.poll_control().expect("a set-aside request");
            assert_eq!(request.payload(), &[b'q', index], "the other requests keep their order");
            request.respond(vec![0]).unwrap();
        }
        for request in queued {
            request.await.unwrap().unwrap();
        }
    })
    .await
    .unwrap();
}
