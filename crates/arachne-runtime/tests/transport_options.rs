//! Typed transport options: an operator relay, no n0 lookup, and deadlines
//! reach the bound endpoint through `ClientConfig`.
use arachne_runtime::{
    Client, ClientConfig, ErrorKind, Network, OperatorRelay, RelayTrust, TransportOptions,
    TransportTimeouts,
};
use std::time::Duration;

fn open(
    network: Network,
    secret: u8,
    transport: TransportOptions,
) -> arachne_runtime::ClientResult<Client> {
    Client::open(ClientConfig {
        network,
        secret: Some([secret; 32]),
        transport,
        storage: None,
    })
}

#[test]
fn wan_without_n0_uses_the_operator_relay_and_deadlines() {
    let timeouts = TransportTimeouts {
        operation: Duration::from_secs(30),
        dial: Duration::from_secs(20),
        gossip_join: Duration::from_secs(9),
        close_drain: Duration::from_secs(7),
    };
    let mut client = open(
        Network::Wan,
        61,
        TransportOptions {
            relay: Some(OperatorRelay {
                urls: vec!["https://relay.example.invalid".into()],
                trust: RelayTrust::WebPki,
            }),
            public_lookup: Some(false),
            timeouts: Some(timeouts),
            deadline: None,
        },
    )
    .unwrap();
    let transport = client.endpoint().unwrap().transport;
    assert!(!transport.public_lookup);
    assert!(transport.operator_relay);
    assert_eq!(transport.timeouts, timeouts);
    client.close().unwrap();
}

#[test]
fn wan_only_can_turn_off_n0_lookup() {
    let mut defaults = open(Network::WanOnly, 62, TransportOptions::default()).unwrap();
    let transport = defaults.endpoint().unwrap().transport;
    assert!(transport.public_lookup);
    assert!(transport.peer_id_lookup);
    assert!(!transport.operator_relay);
    defaults.close().unwrap();

    let mut isolated = open(
        Network::WanOnly,
        63,
        TransportOptions {
            public_lookup: Some(false),
            ..TransportOptions::default()
        },
    )
    .unwrap();
    let transport = isolated.endpoint().unwrap().transport;
    assert!(!transport.public_lookup);
    // With no n0 lookup and no mDNS, this endpoint cannot dial by key alone.
    assert!(!transport.peer_id_lookup);
    isolated.close().unwrap();
}

#[test]
fn invalid_relay_settings_are_invalid_input() {
    for relay in [
        OperatorRelay {
            urls: vec![],
            trust: RelayTrust::WebPki,
        },
        OperatorRelay {
            urls: vec!["not a url".into()],
            trust: RelayTrust::WebPki,
        },
        OperatorRelay {
            urls: vec!["https://relay.example.invalid".into()],
            trust: RelayTrust::CustomRoots(vec![]),
        },
    ] {
        let error = open(
            Network::Wan,
            64,
            TransportOptions {
                relay: Some(relay),
                ..TransportOptions::default()
            },
        )
        .err()
        .expect("invalid relay settings must not bind");
        assert_eq!(error.kind(), ErrorKind::InvalidInput, "{error}");
    }
    let valid = TransportTimeouts {
        operation: Duration::from_secs(1),
        dial: Duration::from_secs(1),
        gossip_join: Duration::from_secs(1),
        close_drain: Duration::from_secs(1),
    };
    for zero in [
        TransportTimeouts {
            operation: Duration::ZERO,
            ..valid
        },
        TransportTimeouts {
            close_drain: Duration::ZERO,
            ..valid
        },
    ] {
        let error = open(
            Network::Direct,
            65,
            TransportOptions {
                timeouts: Some(zero),
                ..TransportOptions::default()
            },
        )
        .err()
        .expect("zero deadlines must not bind");
        assert_eq!(error.kind(), ErrorKind::InvalidInput, "{error}");
    }
}
