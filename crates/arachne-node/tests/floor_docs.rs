use std::{collections::BTreeMap, time::Duration};

use arachne_node::{ConnectionBudget, NetworkProfile, Node, NodeOptions, Permissions};

const WORKSPACE: [u8; 32] = [51; 32];
const REVISION: u64 = 1;

#[tokio::test]
async fn floor_document_replicates_through_an_intermediate_member() {
    let (a, _) = Node::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let (b, _) = Node::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let (c, _) = Node::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let (outsider, _) = Node::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    assert!(
        outsider
            .configure_ptt_floor_document(WORKSPACE, REVISION, &[89; 32], &[outsider.id()])
            .await
            .is_err()
    );
    assert!(
        outsider
            .write_ptt_floor_document(WORKSPACE, REVISION, b"streams/ptt", b"outsider")
            .await
            .is_err()
    );
    let members = BTreeMap::from([
        (a.id(), Permissions::AllTopics),
        (b.id(), Permissions::AllTopics),
        (c.id(), Permissions::AllTopics),
    ]);
    for node in [&a, &b, &c] {
        node.install_verified_policy(WORKSPACE, REVISION, members.clone())
            .await
            .unwrap();
    }

    let endpoints = [a.id(), b.id(), c.id()];
    for node in [&a, &b, &c] {
        node.configure_ptt_floor_document(WORKSPACE, REVISION, &[89; 32], &endpoints)
            .await
            .unwrap();
    }

    // A can reach B and B can reach C; neither A nor C has the other's route.
    // Routes appear after Docs setup, as they can in a self-organizing mesh.
    a.add_address_hint(b.id(), b.address()).await.unwrap();
    b.add_address_hint(a.id(), a.address()).await.unwrap();
    b.add_address_hint(c.id(), c.address()).await.unwrap();
    c.add_address_hint(b.id(), b.address()).await.unwrap();
    assert!(a.address_hint(c.id()).await.is_none());
    assert!(c.address_hint(a.id()).await.is_none());

    c.write_ptt_floor_document(WORKSPACE, REVISION, b"floor/channel-1", b"lease-c")
        .await
        .unwrap();

    let replicated = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let records = a
                .read_ptt_floor_document(WORKSPACE, REVISION)
                .await
                .unwrap();
            if records
                .iter()
                .any(|entry| entry.key == b"floor/channel-1" && entry.value == b"lease-c")
            {
                break records;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("Docs did not converge through member B");

    let entry = replicated
        .iter()
        .find(|entry| entry.key == b"floor/channel-1")
        .unwrap();
    assert_eq!(entry.author, c.id());

    let remaining = BTreeMap::from([
        (a.id(), Permissions::AllTopics),
        (b.id(), Permissions::AllTopics),
    ]);
    c.install_verified_policy(WORKSPACE, REVISION + 1, remaining)
        .await
        .unwrap();
    assert!(
        c.write_ptt_floor_document(WORKSPACE, REVISION, b"streams/ptt", b"revoked")
            .await
            .is_err()
    );

    a.close().await;
    b.close().await;
    c.close().await;
    outsider.close().await;
}

#[tokio::test]
async fn persistent_floor_document_survives_node_restart() {
    let directory = tempfile::tempdir().unwrap();
    let secret = [73; 32];
    let bind = || {
        let mut options = NodeOptions::new(NetworkProfile::Direct);
        options.documents_path = Some(directory.path().to_path_buf());
        Node::bind_with_options(
            "127.0.0.1:0".parse().unwrap(),
            Some(&secret),
            options,
            ConnectionBudget::default(),
        )
    };

    let (node, _) = bind().await.unwrap();
    let members = BTreeMap::from([(node.id(), Permissions::AllTopics)]);
    node.install_verified_policy(WORKSPACE, REVISION, members.clone())
        .await
        .unwrap();
    node.configure_ptt_floor_document(WORKSPACE, REVISION, &[89; 32], &[node.id()])
        .await
        .unwrap();
    node.write_ptt_floor_document(WORKSPACE, REVISION, b"streams/ptt", b"DFAP protected")
        .await
        .unwrap();
    node.close().await;

    let (node, _) = bind().await.unwrap();
    node.install_verified_policy(WORKSPACE, REVISION, members)
        .await
        .unwrap();
    node.configure_ptt_floor_document(WORKSPACE, REVISION, &[89; 32], &[node.id()])
        .await
        .unwrap();
    let records = node
        .read_ptt_floor_document(WORKSPACE, REVISION)
        .await
        .unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].author, node.id());
    assert_eq!(records[0].key, b"streams/ptt");
    assert_eq!(records[0].value, b"DFAP protected");
    node.close().await;
}
