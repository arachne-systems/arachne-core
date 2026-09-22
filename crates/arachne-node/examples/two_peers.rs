//! Two real processes using the library. Policies are explicit test fixtures,
//! delivered over the harness's stdin, NOT a production onboarding mechanism.
use arachne_node::{Node, Permissions, Topic};
use iroh::PublicKey;
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    io,
    net::SocketAddr,
    time::Duration,
};

fn line() -> io::Result<String> {
    let mut text = String::new();
    if io::stdin().read_line(&mut text)? == 0 {
        return Err(io::Error::other("harness disconnected"));
    }
    Ok(text.trim().to_owned())
}

async fn run() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args_os()
        .skip(1)
        .map(|arg| arg.into_string().map_err(|_| "arguments must be UTF-8"))
        .collect::<Result<_, _>>()?;
    let address: SocketAddr = args
        .first()
        .ok_or("provide bind IP:PORT")?
        .parse()?;
    let lan_lookup = args.iter().any(|arg| arg == "--lan-lookup");
    let wan_lookup = args.iter().any(|arg| arg == "--wan-lookup");
    if lan_lookup && wan_lookup {
        return Err("choose only one lookup profile".into());
    }
    let (node, mut messages) = if wan_lookup {
        let secret = iroh::SecretKey::generate().to_bytes();
        Node::bind_wan_with_identity(address, &secret).await?
    } else if lan_lookup {
        Node::bind_lan(address).await?
    } else {
        Node::bind(address).await?
    };
    println!(
        "READY peer={} address={}",
        PublicKey::from_bytes(&node.id())?,
        node.address()
    );
    let config = line()?;
    let (id, address) = if lan_lookup || wan_lookup {
        (config.as_str(), None)
    } else {
        let (id, address) = config
            .split_once(' ')
            .ok_or("expected peer ID and address")?;
        (id, Some(address))
    };
    let peer = *id.parse::<PublicKey>()?.as_bytes();
    if peer == node.id() {
        return Err("expected distinct peers".into());
    }
    if let Some(address) = address {
        node.add_address_hint(peer, address.parse()?).await?;
    }
    let topic = Topic::new("sensors/demo")?;
    let permission = Permissions::Selected {
        publish: BTreeSet::from([topic.clone()]),
        subscribe: BTreeSet::from([topic.clone()]),
    };
    let policy = BTreeMap::from([(node.id(), permission.clone()), (peer, permission)]);
    for workspace in [[1; 32], [2; 32]] {
        node.install_verified_policy(workspace, 1, policy.clone())
            .await?;
    }
    println!("CONFIGURED");
    if line()? != "subscribe" {
        return Err("expected subscribe barrier".into());
    }
    let interest = node.subscribe([1; 32], 1, topic.clone()).await?;
    if interest.admitted.len() != 2 || !interest.failed.is_empty() {
        return Err(format!("subscription failed: {interest:?}").into());
    }
    println!("SUBSCRIBED");
    if line()? != "publish" {
        return Err("expected publish barrier".into());
    }
    let mut payload = node.id().to_vec();
    payload.extend_from_slice(&[0, 255, 128]);
    let report = node.publish([1; 32], 1, topic.clone(), payload).await?;
    if report.admitted.len() != 2 || !report.failed.is_empty() {
        return Err(format!("publication failed: {report:?}").into());
    }
    let isolated = node.publish([2; 32], 1, topic.clone(), vec![9]).await?;
    if !isolated.admitted.is_empty() || !isolated.failed.is_empty() {
        return Err("workspace without subscribers received fanout".into());
    }
    let mut senders = BTreeSet::new();
    for _ in 0..2 {
        let message = tokio::time::timeout(Duration::from_secs(5), messages.recv())
            .await?
            .ok_or("event channel closed")?;
        if message.workspace != [1; 32]
            || message.revision != 1
            || message.topic != topic
            || message.payload[..] != [message.sender.as_slice(), &[0, 255, 128]].concat()
        {
            return Err("received message differs from source fixture".into());
        }
        senders.insert(message.sender);
    }
    if senders != BTreeSet::from([node.id(), peer]) {
        return Err("missing authenticated sender".into());
    }
    println!(
        "VERIFIED remote={} messages=2 payload_bytes=35 isolated_workspace=true",
        id
    );
    if line()? != "stop" {
        return Err("expected stop barrier".into());
    }
    node.close().await;
    println!("PASS");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let _ = tracing_subscriber::fmt()
        .with_target(false)
        .with_writer(std::io::stderr)
        .try_init();
    run().await
}
