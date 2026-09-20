use arachne_node::Node;
use std::time::Duration;

#[tokio::test]
async fn wan_profile_binds_with_the_supplied_identity() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let secret = iroh::SecretKey::generate().to_bytes();
        let expected = *iroh::SecretKey::from_bytes(&secret).public().as_bytes();
        let (node, _) = Node::bind_wan_with_identity("0.0.0.0:0".parse().unwrap(), &secret)
            .await
            .unwrap();
        assert_eq!(node.id(), expected);
        node.close().await;
    })
    .await
    .expect("WAN profile startup exceeded 15 seconds");
}

#[tokio::test]
async fn relay_profile_binds_with_the_supplied_identity() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let secret = iroh::SecretKey::generate().to_bytes();
        let expected = *iroh::SecretKey::from_bytes(&secret).public().as_bytes();
        let (node, _) = Node::bind_relay_with_identity("0.0.0.0:0".parse().unwrap(), &secret)
            .await
            .unwrap();
        assert_eq!(node.id(), expected);
        assert_eq!(node.address(), "0.0.0.0:0".parse().unwrap());
        node.close().await;
    })
    .await
    .expect("relay profile startup exceeded 15 seconds");
}

#[tokio::test]
async fn wan_only_profile_keeps_direct_transport_and_identity() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let secret = iroh::SecretKey::generate().to_bytes();
        let expected = *iroh::SecretKey::from_bytes(&secret).public().as_bytes();
        let (node, _) = Node::bind_wan_only_with_identity("0.0.0.0:0".parse().unwrap(), &secret)
            .await
            .unwrap();
        assert_eq!(node.id(), expected);
        assert_ne!(node.address(), "0.0.0.0:0".parse().unwrap());
        node.close().await;
    })
    .await
    .expect("WAN-only profile startup exceeded 15 seconds");
}
