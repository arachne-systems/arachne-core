#![cfg(feature = "tor")]

use arachne_runtime::{Client, ClientConfig, Network};

/// Requires a local Tor daemon and Tor network access.
#[test]
#[ignore = "requires a local Tor daemon and Tor network access"]
fn typed_client_opens_tor_only_endpoint_with_the_supplied_identity() {
    assert!(
        Client::open(ClientConfig {
            network: Network::Tor,
            secret: None,
        })
        .is_err()
    );

    let secret = [81; 32];
    let mut client = Client::open(ClientConfig {
        network: Network::Tor,
        secret: Some(secret),
    })
    .unwrap();
    assert_eq!(
        client.endpoint().unwrap().endpoint_key,
        *iroh::SecretKey::from_bytes(&secret).public().as_bytes()
    );
    client.close().unwrap();
}
