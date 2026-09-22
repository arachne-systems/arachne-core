//! Minimal non-ATAK consumer using the typed runtime seam.
//!
//! Run with:
//! `cargo run --offline -p arachne-runtime --example typed_pubsub`

use arachne_runtime::{Client, ClientConfig, Network, PeerPolicy};
use std::{
    error::Error,
    thread,
    time::{Duration, Instant},
};

fn main() -> Result<(), Box<dyn Error>> {
    let mut publisher = Client::open(ClientConfig {
        network: Network::Direct,
        secret: Some([41; 32]),
    })?;
    let mut subscriber = Client::open(ClientConfig {
        network: Network::Direct,
        secret: Some([42; 32]),
    })?;

    let publisher_endpoint = publisher.endpoint()?;
    let subscriber_endpoint = subscriber.endpoint()?;
    let workspace = [43; 32];
    let topic = "streams/example";
    let policy = [
        PeerPolicy {
            peer: publisher_endpoint.endpoint_key,
            publish: vec![topic.into()],
            subscribe: Vec::new(),
        },
        PeerPolicy {
            peer: subscriber_endpoint.endpoint_key,
            publish: Vec::new(),
            subscribe: vec![topic.into()],
        },
    ];

    publisher.add_address_hint(
        subscriber_endpoint.endpoint_key,
        &subscriber_endpoint
            .bound_address
            .replace("0.0.0.0:", "127.0.0.1:"),
    )?;
    subscriber.add_address_hint(
        publisher_endpoint.endpoint_key,
        &publisher_endpoint
            .bound_address
            .replace("0.0.0.0:", "127.0.0.1:"),
    )?;
    publisher.install_policy(workspace, 1, &policy)?;
    subscriber.install_policy(workspace, 1, &policy)?;
    subscriber.set_interest(workspace, 1, topic, true)?;

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(observation) = subscriber.poll_interest()? {
            if !observation.admission.failed.is_empty() {
                return Err(format!("interest failed: {:?}", observation.admission.failed).into());
            }
            break;
        }
        if Instant::now() >= deadline {
            return Err("interest did not settle before the deadline".into());
        }
        thread::sleep(Duration::from_millis(10));
    }

    let payload = vec![0, 1, 2, 255];
    let report = publisher.publish(workspace, 1, topic, payload.clone())?;
    assert_eq!(report.admitted, vec![subscriber_endpoint.endpoint_key]);

    loop {
        if let Some(publication) = subscriber.poll()? {
            assert_eq!(publication.workspace, workspace);
            assert_eq!(publication.topic, topic);
            assert_eq!(publication.payload, payload);
            break;
        }
        if Instant::now() >= deadline {
            return Err("publication did not arrive before the deadline".into());
        }
        thread::sleep(Duration::from_millis(10));
    }

    publisher.close()?;
    subscriber.close()?;
    println!("typed opaque publish/receive passed");
    Ok(())
}
