use arachne_node::{DeliveryClass, Node, Permissions, Topic};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

#[tokio::test]
async fn critical_and_current_progress_while_bulk_is_full() {
    let (mut server, mut messages) = Node::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let (client, _) = Node::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let bulk = Topic::new("resources/chunks").unwrap();
    let chat = Topic::new("collaboration/chat").unwrap();
    let current = Topic::new("observations/current").unwrap();
    for workspace in [[1; 32], [2; 32]] {
        server
            .install_verified_policy(
                workspace,
                1,
                BTreeMap::from([(server.id(), Permissions::AllTopics)]),
            )
            .await
            .unwrap();
        for topic in [&bulk, &chat, &current] {
            server.subscribe(workspace, 1, topic.clone()).await.unwrap();
        }
    }

    for chunk in 0_u8..64 {
        let report = server
            .publish_with_class([1; 32], 1, bulk.clone(), DeliveryClass::Bulk, vec![chunk])
            .await
            .unwrap();
        assert_eq!(report.admitted, vec![server.id()]);
    }
    let full = server
        .publish_with_class([1; 32], 1, bulk.clone(), DeliveryClass::Bulk, vec![64])
        .await
        .unwrap();
    assert!(full.admitted.is_empty());
    assert_eq!(full.failed.len(), 1);

    for value in 0_u8..100 {
        let report = server
            .publish_with_class(
                [1; 32],
                1,
                current.clone(),
                DeliveryClass::Current {
                    replacement_key: [9; 32],
                },
                vec![value],
            )
            .await
            .unwrap();
        assert_eq!(report.admitted, vec![server.id()]);
    }
    server
        .publish_with_class(
            [2; 32],
            1,
            current.clone(),
            DeliveryClass::Current {
                replacement_key: [9; 32],
            },
            vec![7],
        )
        .await
        .unwrap();
    for message in 0_u8..16 {
        server
            .publish([1; 32], 1, chat.clone(), vec![message])
            .await
            .unwrap();
    }

    client
        .add_address_hint(server.id(), server.address())
        .await
        .unwrap();
    let recovery = tokio::spawn(client.request_control(server.id(), b"recover"));
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if let Some(request) = server.poll_control() {
            assert_eq!(request.payload(), b"recover");
            request.respond(b"ready".to_vec()).unwrap();
            break;
        }
        assert!(
            Instant::now() < deadline,
            "control was starved by bulk data"
        );
        tokio::task::yield_now().await;
    }
    assert_eq!(recovery.await.unwrap().unwrap(), b"ready");

    for message in 0_u8..8 {
        assert_eq!(messages.recv().await.unwrap().payload, vec![message]);
    }
    let first_current = messages.recv().await.unwrap();
    assert_eq!(first_current.workspace, [1; 32]);
    assert_eq!(first_current.payload, vec![99]);
    for message in 8_u8..16 {
        assert_eq!(messages.recv().await.unwrap().payload, vec![message]);
    }
    assert_eq!(messages.recv().await.unwrap().payload, vec![0]);
    let second_current = messages.recv().await.unwrap();
    assert_eq!(second_current.workspace, [2; 32]);
    assert_eq!(second_current.payload, vec![7]);

    let retried = server
        .publish_to_with_class(
            [1; 32],
            1,
            bulk,
            vec![server.id()],
            vec![[8; 32]],
            DeliveryClass::Bulk,
            vec![64],
        )
        .await
        .unwrap();
    assert_eq!(retried.admitted, vec![server.id()]);

    server.close().await;
    client.close().await;
}
