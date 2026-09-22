use arachne_node::{DeliveryClass, Error, Node, Permissions, Topic};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};

#[tokio::test]
async fn transport_metrics_observe_reused_paths_without_retaining_closed_connections() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (sender, _) = Node::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let (mut receiver, _) = Node::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let (unrelated, _) = Node::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        assert_eq!(sender.transport_metrics().sent_bytes, 0);
        sender
            .add_address_hint(receiver.id(), receiver.address())
            .await
            .unwrap();
        let send = tokio::spawn(sender.request_control(receiver.id(), &[7; 1024]));
        let request = loop {
            if let Some(request) = receiver.poll_control() {
                break request;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        };
        let measured = sender.transport_metrics();
        assert!(measured.sent_bytes >= 1024);
        assert!(measured.received_bytes > 0);
        assert!(
            measured
                .paths
                .iter()
                .any(|path| path.endpoint == receiver.id() && path.route == "direct")
        );
        assert!(!measured.paths_limited);
        assert_eq!(unrelated.transport_metrics().sent_bytes, 0);
        assert!(receiver.transport_metrics().received_bytes >= 1024);
        request.respond(vec![8; 512]).unwrap();
        assert_eq!(send.await.unwrap().unwrap(), vec![8; 512]);
        assert!(!sender.transport_metrics().paths.is_empty());
        receiver.close().await;
        loop {
            if sender.transport_metrics().paths.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(sender.transport_metrics().sent_bytes >= measured.sent_bytes);
        sender.close().await;
        unrelated.close().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn supplied_identity_survives_rebind_without_restoring_authority() {
    // Fixture only; production callers must generate and protect random credentials.
    let seed = [37; 32];
    let (first, _) = Node::bind_with_identity("127.0.0.1:0".parse().unwrap(), &seed)
        .await
        .unwrap();
    let id = first.id();
    let topic = Topic::new("streams/sample").unwrap();
    first
        .install_verified_policy(
            [1; 32],
            1,
            BTreeMap::from([(
                id,
                Permissions::Selected {
                    publish: BTreeSet::from([topic.clone()]),
                    subscribe: BTreeSet::new(),
                },
            )]),
        )
        .await
        .unwrap();
    first.close().await;
    let (restarted, _) = Node::bind_with_identity("127.0.0.1:0".parse().unwrap(), &seed)
        .await
        .unwrap();
    assert_eq!(restarted.id(), id);
    assert!(matches!(
        restarted.publish([1; 32], 1, topic, vec![1]).await,
        Err(Error::Routing(_))
    ));
    restarted.close().await;
    let (other, _) = Node::bind_with_identity("127.0.0.1:0".parse().unwrap(), &[38; 32])
        .await
        .unwrap();
    assert_ne!(other.id(), id);
    other.close().await;
}

#[tokio::test]
async fn withheld_ack_reports_stage_without_claiming_admission() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let alpn = b"data-fabric/pubsub-experiment/1";
        let (node, _messages) = Node::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        // Make the stalled peer sort first, so serial fanout cannot pass by luck.
        let mut seeds = [[11; 32], [12; 32]];
        seeds.sort_by_key(|seed| *iroh::SecretKey::from_bytes(seed).public().as_bytes());
        let (healthy, mut healthy_events) =
            Node::bind_with_identity("127.0.0.1:0".parse().unwrap(), &seeds[1])
                .await.unwrap();
        let peer = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .secret_key(iroh::SecretKey::from_bytes(&seeds[0]))
            .clear_relay_transports()
            .clear_ip_transports()
            .bind_addr("127.0.0.1:0")
            .unwrap()
            .alpns(vec![alpn.to_vec()])
            .bind()
            .await
            .unwrap();
        let peer_id = *peer.id().as_bytes();
        let topic = Topic::new("streams/sample").unwrap();
        node.add_address_hint(peer_id, peer.bound_sockets()[0])
            .await
            .unwrap();
        node.install_verified_policy(
            [1; 32],
            1,
            BTreeMap::from([
                (
                    node.id(),
                    Permissions::Selected {
                        publish: BTreeSet::from([topic.clone()]),
                        subscribe: BTreeSet::new(),
                    },
                ),
                (
                    peer_id,
                    Permissions::Selected {
                        publish: BTreeSet::new(),
                        subscribe: BTreeSet::from([topic.clone()]),
                    },
                ),
            ]),
        )
        .await
        .unwrap();

        let subscription = peer
            .connect(
                iroh::EndpointAddr::new(iroh::PublicKey::from_bytes(&node.id()).unwrap())
                    .with_ip_addr(node.address()),
                alpn,
            )
            .await
            .unwrap();
        let (mut send, mut recv) = subscription.open_bi().await.unwrap();
        send.write_all(&[0]).await.unwrap();
        send.write_all(
            &postcard::to_allocvec(&(1_u8, [1_u8;32], 1_u64, "streams/sample", DeliveryClass::Critical, 0_u8))
            .unwrap(),
        )
        .await
        .unwrap();
        send.finish().unwrap();
        assert_eq!(recv.read_to_end(1).await.unwrap(), [1]);
        subscription.close(0u8.into(), b"subscribed");

        let policy = BTreeMap::from([
            (node.id(), Permissions::Selected { publish: BTreeSet::from([topic.clone()]), subscribe: BTreeSet::new() }),
            (peer_id, Permissions::Selected { publish: BTreeSet::new(), subscribe: BTreeSet::from([topic.clone()]) }),
            (healthy.id(), Permissions::Selected { publish: BTreeSet::new(), subscribe: BTreeSet::from([topic.clone()]) }),
        ]);
        // Exercise both subscribers at the same current policy revision.
        node.install_verified_policy([1;32], 2, policy.clone()).await.unwrap();
        healthy.install_verified_policy([1;32], 2, policy).await.unwrap();
        node.add_address_hint(healthy.id(), healthy.address()).await.unwrap();
        healthy.add_address_hint(node.id(), node.address()).await.unwrap();
        assert!(healthy.subscribe([1;32], 2, topic.clone()).await.unwrap().failed.is_empty());
        let subscription = peer.connect(
            iroh::EndpointAddr::new(iroh::PublicKey::from_bytes(&node.id()).unwrap()).with_ip_addr(node.address()), alpn
        ).await.unwrap();
        let (mut send, mut recv) = subscription.open_bi().await.unwrap();
        send.write_all(&[0]).await.unwrap();
        send.write_all(&postcard::to_allocvec(&(1_u8, [1_u8;32], 2_u64, "streams/sample", DeliveryClass::Critical, 0_u8)).unwrap()).await.unwrap();
        send.finish().unwrap();
        assert_eq!(recv.read_to_end(1).await.unwrap(), [1]);
        subscription.close(0u8.into(), b"subscribed");

        let (release, released) = tokio::sync::oneshot::channel();
        let responder = peer.clone();
        let stalled = tokio::spawn(async move {
            let connection = responder.accept().await.unwrap().await.unwrap();
            let (_send, mut recv) = connection.accept_bi().await.unwrap();
            let bytes = recv.read_to_end(128 * 1024).await.unwrap();
            assert_eq!(bytes[0], 0);
            assert_eq!(bytes[1..], postcard::to_allocvec(&(1_u8, [1_u8;32], 2_u64,
                "streams/sample", DeliveryClass::Critical, 2_u8, &[42_u8][..])).unwrap());
            // Keep the authenticated stream open without acknowledging receipt.
            released.await.unwrap();
            connection.close(0u8.into(), b"stall checked");
        });
        let (report, received) = tokio::join!(
            node.publish([1; 32], 2, topic, vec![42]),
            tokio::time::timeout(Duration::from_secs(2), healthy_events.recv())
        );
        assert_eq!(received.expect("healthy peer blocked behind stalled acknowledgment").unwrap().payload, vec![42]);
        let report = report.unwrap();
        assert_eq!(report.admitted, vec![healthy.id()]);
        assert_eq!(report.failed.len(), 1);
        assert_eq!(report.failed[0].0, peer_id);
        assert!(matches!(
            report.failed[0].1,
            Error::Timeout("read acknowledgment")
        ));
        release.send(()).unwrap();
        stalled.await.unwrap();
        peer.close().await;
        healthy.close().await;
        node.close().await;
    })
    .await
    .expect("withheld acknowledgment test deadline");
}

#[tokio::test]
async fn real_peers_route_non_cot_and_reject_stale_authority() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let (feed, _feed_events) = Node::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let (sink, mut events) = Node::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        feed.add_address_hint(sink.id(), sink.address())
            .await
            .unwrap();
        sink.add_address_hint(feed.id(), feed.address())
            .await
            .unwrap();
        let topic = Topic::new("streams/sample").unwrap();
        let workspace_a = [10; 32];
        let workspace_b = [20; 32];
        let policy = BTreeMap::from([
            (
                feed.id(),
                Permissions::Selected {
                    publish: BTreeSet::from([topic.clone()]),
                    subscribe: BTreeSet::new(),
                },
            ),
            (
                sink.id(),
                Permissions::Selected {
                    publish: BTreeSet::new(),
                    subscribe: BTreeSet::from([topic.clone()]),
                },
            ),
        ]);
        for node in [&feed, &sink] {
            for workspace in [workspace_a, workspace_b] {
                node.install_verified_policy(workspace, 1, policy.clone())
                    .await
                    .unwrap();
            }
        }
        let subscribed = sink.subscribe(workspace_a, 1, topic.clone()).await.unwrap();
        assert_eq!(subscribed.admitted, vec![feed.id()]);
        assert!(subscribed.failed.is_empty());
        // Independent example payloads: the fabric parses none of their formats.
        for bytes in [
            vec![0, 1, 255, 2, 128],
            br#"{"event":"mode.changed","value":"ready"}"#.to_vec(),
            vec![0, 1, 255, 2, 129],
        ] {
            let report = feed
                .publish(workspace_a, 1, topic.clone(), bytes.clone())
                .await
                .unwrap();
            assert_eq!(report.admitted, vec![sink.id()]);
            assert!(report.failed.is_empty());
            let message = events.recv().await.unwrap();
            assert_eq!(message.payload, bytes);
            assert_eq!(message.sender, feed.id());
            assert_eq!(message.workspace, workspace_a);
        }
        let isolated = feed
            .publish(workspace_b, 1, topic.clone(), vec![99])
            .await
            .unwrap();
        assert!(isolated.admitted.is_empty());
        assert!(isolated.failed.is_empty());
        assert!(events.try_recv().is_err());
        let unsubscribed = sink
            .unsubscribe(workspace_a, 1, topic.clone())
            .await
            .unwrap();
        assert_eq!(unsubscribed.admitted, vec![feed.id()]);
        assert!(
            feed.publish(workspace_a, 1, topic.clone(), vec![4])
                .await
                .unwrap()
                .admitted
                .is_empty()
        );
        sink.subscribe(workspace_a, 1, topic.clone()).await.unwrap();
        assert!(matches!(
            sink.publish(workspace_a, 1, topic.clone(), vec![1]).await,
            Err(Error::Routing(_))
        ));

        // Receiver-side enforcement: publisher still holds its previous permission.
        let mut revoked = policy.clone();
        let Permissions::Selected { publish, .. } = revoked.get_mut(&feed.id()).unwrap() else {
            panic!("expected selected policy")
        };
        publish.clear();
        sink.install_verified_policy(workspace_a, 2, revoked)
            .await
            .unwrap();
        let rejected = feed
            .publish(workspace_a, 1, topic.clone(), vec![9])
            .await
            .unwrap();
        assert!(rejected.admitted.is_empty());
        assert_eq!(rejected.failed.len(), 1);
        assert!(matches!(rejected.failed[0].1, Error::Rejected));
        assert!(events.try_recv().is_err());

        // A tampered publisher policy cannot override the receiver's same-revision ACL.
        feed.install_verified_policy(workspace_a, 2, policy.clone())
            .await
            .unwrap();
        let denied = feed
            .publish(workspace_a, 2, topic.clone(), vec![8])
            .await
            .unwrap();
        assert!(denied.admitted.is_empty());
        assert!(matches!(denied.failed[0].1, Error::Rejected));
        assert!(events.try_recv().is_err());

        let unsubscribed = sink
            .unsubscribe(workspace_b, 1, topic.clone())
            .await
            .unwrap();
        assert!(unsubscribed.failed.is_empty());
        assert!(
            feed.publish(workspace_b, 1, topic, vec![3])
                .await
                .unwrap()
                .admitted
                .is_empty()
        );
        feed.close().await;
        sink.close().await;
        assert!(events.recv().await.is_none());
    })
    .await
    .expect("live pub/sub deadline");
}

#[tokio::test]
async fn recipient_scoped_publication_reaches_only_selected_endpoint() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let (sender, _sender_events) = Node::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let (recipient, mut recipient_events) =
            Node::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let (other, mut other_events) = Node::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        for (from, to) in [(&sender, &recipient), (&sender, &other)] {
            from.add_address_hint(to.id(), to.address()).await.unwrap();
            to.add_address_hint(from.id(), from.address())
                .await
                .unwrap();
        }
        let topic = Topic::new("streams/opaque").unwrap();
        let policy = BTreeMap::from([
            (
                sender.id(),
                Permissions::Selected {
                    publish: BTreeSet::from([topic.clone()]),
                    subscribe: BTreeSet::new(),
                },
            ),
            (
                recipient.id(),
                Permissions::Selected {
                    publish: BTreeSet::new(),
                    subscribe: BTreeSet::from([topic.clone()]),
                },
            ),
            (
                other.id(),
                Permissions::Selected {
                    publish: BTreeSet::new(),
                    subscribe: BTreeSet::from([topic.clone()]),
                },
            ),
        ]);
        for node in [&sender, &recipient, &other] {
            node.install_verified_policy([9; 32], 1, policy.clone())
                .await
                .unwrap();
        }
        let recipient_member = [3; 32];
        let refused = sender.publish_to([9; 32], 1, topic.clone(),
            vec![recipient.id()], vec![recipient_member], vec![1]).await.unwrap();
        assert!(refused.admitted.is_empty(), "an unsubscribed recipient was admitted");
        assert_eq!(refused.failed.len(), 1, "missing per-target non-delivery result");
        assert_eq!(refused.failed[0].0, recipient.id());
        assert!(recipient_events.try_recv().is_err());
        // Both receivers want the topic; only the selected audience gets this item.
        // The sender has publication permission but no receive permission/interest.
        for node in [&recipient, &other] {
            assert!(node.subscribe([9; 32], 1, topic.clone()).await.unwrap().failed.is_empty());
        }
        let report = sender
            .publish_to(
                [9; 32],
                1,
                topic.clone(),
                vec![recipient.id()],
                vec![recipient_member],
                vec![0, 255, 42],
            )
            .await
            .unwrap();
        assert_eq!(report.admitted, vec![recipient.id()]);
        assert!(report.failed.is_empty());
        let delivered = recipient_events.recv().await.unwrap();
        assert_eq!(delivered.payload, vec![0, 255, 42]);
        assert_eq!(delivered.recipients, vec![recipient_member]);
        assert!(
            other_events.try_recv().is_err(),
            "unselected endpoint received a direct publication"
        );
        recipient.unsubscribe([9; 32], 1, topic.clone()).await.unwrap();
        let mut endpoints = vec![recipient.id(), other.id()];
        endpoints.sort_unstable();
        let partial = sender.publish_to([9; 32], 1, topic.clone(), endpoints,
            vec![recipient_member, [4; 32]], vec![2]).await.unwrap();
        assert_eq!(partial.admitted, vec![other.id()]);
        assert_eq!(partial.failed.len(), 1);
        assert_eq!(partial.failed[0].0, recipient.id());
        assert!(recipient_events.try_recv().is_err());
        assert_eq!(other_events.recv().await.unwrap().payload, vec![2]);
        recipient.subscribe([9; 32], 1, topic.clone()).await.unwrap();
        let resumed = sender.publish_to([9; 32], 1, topic.clone(), vec![recipient.id()],
            vec![recipient_member], vec![3]).await.unwrap();
        assert_eq!(resumed.admitted, vec![recipient.id()]);
        assert!(resumed.failed.is_empty());
        assert_eq!(recipient_events.recv().await.unwrap().payload, vec![3]);
        assert!(other_events.try_recv().is_err());
        assert!(
            sender
                .publish_to(
                    [9; 32],
                    1,
                    topic,
                    vec![other.id()],
                    vec![[4; 32], [3; 32]],
                    vec![1]
                )
                .await
                .is_err()
        );
        sender.close().await;
        recipient.close().await;
        other.close().await;
    })
    .await
    .expect("recipient-scoped routing deadline");
}

#[tokio::test]
async fn queue_pressure_is_not_a_false_success() {
    let (node, mut events) = Node::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let topic = Topic::new("data").unwrap();
    node.install_verified_policy(
        [1; 32],
        1,
        BTreeMap::from([(
            node.id(),
            Permissions::Selected {
                publish: BTreeSet::from([topic.clone()]),
                subscribe: BTreeSet::from([topic.clone()]),
            },
        )]),
    )
    .await
    .unwrap();
    node.subscribe([1; 32], 1, topic.clone()).await.unwrap();
    for _ in 0..256 {
        assert_eq!(
            node.publish([1; 32], 1, topic.clone(), vec![1])
                .await
                .unwrap()
                .admitted
                .len(),
            1
        );
    }
    let full = node
        .publish([1; 32], 1, topic.clone(), vec![2])
        .await
        .unwrap();
    assert!(full.admitted.is_empty());
    assert!(matches!(full.failed[0].1, Error::Backpressure));
    assert!(matches!(
        node.publish([1; 32], 1, topic.clone(), vec![0; 16385])
            .await,
        Err(Error::TooLarge)
    ));
    assert_eq!(events.recv().await.unwrap().payload, vec![1]);
    assert_eq!(
        node.publish([1; 32], 1, topic, vec![3])
            .await
            .unwrap()
            .admitted
            .len(),
        1
    );
    node.close().await;
}

#[tokio::test]
async fn wire_sender_cannot_claim_the_receivers_identity() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (node, mut messages) = Node::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let topic = Topic::new("data").unwrap();
        node.install_verified_policy(
            [1; 32],
            1,
            BTreeMap::from([(
                node.id(),
                Permissions::Selected {
                    publish: BTreeSet::from([topic.clone()]),
                    subscribe: BTreeSet::from([topic.clone()]),
                },
            )]),
        )
        .await
        .unwrap();
        node.subscribe([1; 32], 1, topic).await.unwrap();
        let stranger = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .clear_ip_transports()
            .bind_addr("127.0.0.1:0")
            .unwrap()
            .bind()
            .await
            .unwrap();
        let mut frame = postcard::to_allocvec(&(1_u8, [1_u8;32], 1_u64, "data", DeliveryClass::Critical, 2_u8, &[99_u8][..])).unwrap();
        for spoof_sender in [false, true] {
            if spoof_sender {
                frame.extend_from_slice(&node.id());
            }
            let peer = iroh::PublicKey::from_bytes(&node.id()).unwrap();
            let conn = stranger
                .connect(
                    iroh::EndpointAddr::new(peer).with_ip_addr(node.address()),
                    b"data-fabric/pubsub-experiment/1",
                )
                .await
                .unwrap();
            let (mut send, mut recv) = conn.open_bi().await.unwrap();
            send.write_all(&[0]).await.unwrap();
            send.write_all(&frame)
                .await
                .unwrap();
            send.finish().unwrap();
            assert_eq!(recv.read_to_end(1).await.unwrap(), [0]);
            conn.close(0u8.into(), b"negative case checked");
            assert!(messages.try_recv().is_err());
        }
        stranger.close().await;
        node.close().await;
    })
    .await
    .expect("unauthorized wire test deadline");
}

#[tokio::test]
async fn control_failure_distinguishes_unsent_from_unknown_outcome() {
    let (client, _) = Node::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let (mut server, _) = Node::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let peer = server.id();
    client
        .add_address_hint(peer, server.address())
        .await
        .unwrap();
    let receive_without_reply = async {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let request = loop {
            if let Some(request) = server.poll_control() {
                break request;
            }
            assert!(tokio::time::Instant::now() < deadline);
            tokio::time::sleep(Duration::from_millis(5)).await;
        };
        assert_eq!(request.payload(), b"attempt");
        tokio::time::sleep(Duration::from_secs(6)).await;
        drop(request);
    };
    let (result, ()) = tokio::join!(
        client.request_control(peer, b"attempt"),
        receive_without_reply
    );
    assert!(
        !result
            .unwrap_err()
            .to_string()
            .contains("control request not sent")
    );
    server.close().await;
    let error = client.request_control(peer, b"attempt").await.unwrap_err();
    assert!(
        error.to_string().contains("control request not sent"),
        "closed endpoint: {error}"
    );
    client.close().await;
}

#[tokio::test]
async fn control_peer_identity_comes_from_transport() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (client, _) = Node::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let (mut server, _) = Node::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        client
            .add_address_hint(server.id(), server.address())
            .await
            .unwrap();
        let peer = server.id();
        let expected = client.id();
        let body = br#"{"claimed_peer":"someone else"}"#;
        let responder = async {
            let request = loop {
                if let Some(request) = server.poll_control() {
                    break request;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            };
            assert_eq!(request.peer(), expected);
            assert_eq!(request.payload(), body);
            request.respond(vec![0, 255, 42]).unwrap();
        };
        let (reply, ()) = tokio::join!(client.request_control(peer, body), responder);
        assert_eq!(reply.unwrap(), vec![0, 255, 42]);
        assert!(matches!(
            client.request_control(peer, &vec![0; 32769]).await,
            Err(Error::TooLarge)
        ));
        client.close().await;
        server.close().await;
    })
    .await
    .expect("control identity check deadline");
}

#[tokio::test]
async fn authorized_subscription_learns_return_path_but_rejection_does_not() {
    let (publisher, _) = Node::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let (subscriber, mut events) = Node::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let (outsider, _) = Node::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let topic = Topic::new("streams/sample").unwrap();
    let permissions = Permissions::Selected {
        publish: BTreeSet::from([topic.clone()]),
        subscribe: BTreeSet::from([topic.clone()]),
    };
    let policy = BTreeMap::from([
        (publisher.id(), permissions.clone()),
        (subscriber.id(), permissions.clone()),
    ]);
    publisher
        .install_verified_policy([1; 32], 1, policy.clone())
        .await
        .unwrap();
    subscriber
        .install_verified_policy([1; 32], 1, policy.clone())
        .await
        .unwrap();
    let mut forged = policy;
    forged.insert(outsider.id(), permissions);
    outsider
        .install_verified_policy([1; 32], 1, forged.clone())
        .await
        .unwrap();
    outsider
        .add_address_hint(publisher.id(), publisher.address())
        .await
        .unwrap();
    let rejected = outsider.subscribe([1; 32], 1, topic.clone()).await.unwrap();
    assert!(
        rejected
            .failed
            .iter()
            .any(|(id, error)| *id == publisher.id() && matches!(error, Error::Rejected))
    );
    // Only the subscriber knows an initial address. The publisher learns its
    // authenticated source path when admitting the subscription.
    subscriber
        .add_address_hint(publisher.id(), publisher.address())
        .await
        .unwrap();
    assert!(
        subscriber
            .subscribe([1; 32], 1, topic.clone())
            .await
            .unwrap()
            .failed
            .is_empty()
    );
    let sent = publisher
        .publish([1; 32], 1, topic.clone(), vec![0, 255, 42])
        .await
        .unwrap();
    assert!(sent.failed.is_empty());
    assert_eq!(sent.admitted, vec![subscriber.id()]);
    let received = tokio::time::timeout(Duration::from_secs(5), events.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received.payload, vec![0, 255, 42]);
    // Granting authority later cannot turn the rejected attempt into an address
    // hint. The outsider must establish a newly authorized path.
    publisher
        .install_verified_policy([1; 32], 2, forged)
        .await
        .unwrap();
    let attempts = publisher.subscribe([1; 32], 2, topic).await.unwrap();
    assert!(
        attempts
            .failed
            .iter()
            .any(|(id, error)| *id == outsider.id() && matches!(error, Error::MissingPeer))
    );
    publisher.close().await;
    subscriber.close().await;
    outsider.close().await;
}

#[tokio::test]
async fn stalled_data_connections_do_not_consume_control_capacity() {
    let (mut server, _events) = Node::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let (client, _) = Node::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    client
        .add_address_hint(server.id(), server.address())
        .await
        .unwrap();
    let attacker = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .clear_relay_transports()
        .clear_ip_transports()
        .bind_addr("127.0.0.1:0")
        .unwrap()
        .bind()
        .await
        .unwrap();
    let destination = iroh::EndpointAddr::new(iroh::PublicKey::from_bytes(&server.id()).unwrap())
        .with_ip_addr(server.address());
    let mut stalled = Vec::new();
    // Fill the data budget with authenticated connections holding incomplete frames.
    // This is a data-slot attack, not a handshake/CPU flood or membership test.
    for _ in 0..32 {
        let connection = attacker
            .connect(destination.clone(), b"data-fabric/pubsub-experiment/1")
            .await
            .unwrap();
        let (mut send, recv) = connection.open_bi().await.unwrap();
        send.write_all(&[1]).await.unwrap();
        stalled.push((connection, send, recv));
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        stalled
            .iter()
            .all(|(connection, _, _)| connection.close_reason().is_none())
    );
    let started = std::time::Instant::now();
    let request = client.request_control(server.id(), b"control-under-load");
    let result = tokio::time::timeout(Duration::from_secs(2), async {
        let responder = async {
            loop {
                if let Some(request) = server.poll_control() {
                    assert_eq!(request.peer(), client.id());
                    assert_eq!(request.payload(), b"control-under-load");
                    request.respond(b"accepted".to_vec()).unwrap();
                    break;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        };
        let (reply, ()) = tokio::join!(request, responder);
        reply
    })
    .await;
    let elapsed = started.elapsed();
    for (connection, _, _) in &stalled {
        connection.close(0u32.into(), b"test complete");
    }
    drop(stalled);
    attacker.close().await;
    client.close().await;
    server.close().await;
    assert_eq!(
        result
            .expect("control starved behind stalled data")
            .unwrap(),
        b"accepted"
    );
    println!(
        "32 stalled data connections; authenticated control response in {elapsed:?}; all endpoints closed"
    );
}

#[tokio::test]
async fn durable_control_reply_can_outlast_a_data_operation() {
    let (client, _) = Node::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let (mut server, _) = Node::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let peer = server.id();
    client
        .add_address_hint(peer, server.address())
        .await
        .unwrap();
    let respond = async {
        let request = loop {
            if let Some(request) = server.poll_control() {
                break request;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        };
        // Models an occupied host worker plus a durable membership write.
        tokio::time::sleep(Duration::from_secs(6)).await;
        request.respond(b"saved".to_vec())
    };
    let (reply, sent) = tokio::time::timeout(Duration::from_secs(15), async {
        tokio::join!(client.request_control(peer, b"admit"), respond)
    })
    .await
    .unwrap();
    assert!(sent.is_ok(), "durable reply expired: {sent:?}");
    assert_eq!(reply.unwrap(), b"saved");
    client.close().await;
    server.close().await;
}
