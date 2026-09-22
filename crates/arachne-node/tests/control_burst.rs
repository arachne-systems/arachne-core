use arachne_node::{Node, PeerId};
use std::time::{Duration, Instant};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "explicit local transport burst run"]
async fn authenticated_control_burst_handles_500_clients() {
    let members = std::env::var("ARACHNE_CONTROL_BURST_MEMBERS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(500);
    let (mut owner, _) = Node::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let owner_peer: PeerId = owner.id();
    let owner_address = owner.address();
    let started = Instant::now();

    let mut clients = tokio::task::JoinSet::new();
    for index in 0..members {
        clients.spawn(async move {
            let mut seed = [0; 32];
            seed[..8].copy_from_slice(&(index as u64 + 1).to_be_bytes());
            Node::bind_with_identity("127.0.0.1:0".parse().unwrap(), &seed)
                .await
                .map(|node| node.0)
        });
    }
    let mut nodes = Vec::with_capacity(members);
    while let Some(result) = clients.join_next().await {
        nodes.push(result.unwrap().unwrap());
    }

    let mut requests = tokio::task::JoinSet::new();
    for node in nodes {
        requests.spawn(async move {
            node.add_address_hint(owner_peer, owner_address).await?;
            let result = node.request_control(owner_peer, b"burst").await;
            node.close().await;
            result
        });
    }

    let mut received = 0;
    let receive_deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    while received < members && tokio::time::Instant::now() < receive_deadline {
        let mut drained = 0;
        while drained < 8 {
            let Some(request) = owner.poll_control() else {
                break;
            };
            request.respond(b"ok".to_vec()).unwrap();
            received += 1;
            drained += 1;
        }
        if drained == 0 {
            tokio::task::yield_now().await;
        }
    }

    let mut succeeded = 0;
    let mut failed = 0;
    while let Some(result) = requests.join_next().await {
        match result.unwrap() {
            Ok(reply) if reply == b"ok" => succeeded += 1,
            Ok(_) | Err(_) => failed += 1,
        }
    }
    owner.close().await;
    println!(
        "control_burst members={members} received={received} succeeded={succeeded} failed={failed} elapsed_ms={}",
        started.elapsed().as_millis()
    );
    assert_eq!(received, members);
    assert_eq!(succeeded, members);
    assert_eq!(failed, 0);
}
