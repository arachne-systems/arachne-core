use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    time::{Duration, Instant},
};

use arachne_node::{Node, Permissions, Topic};
use serde_json::json;

const PARTICIPANTS: usize = 12;
const PUBLICATIONS: usize = 20;
const PAYLOAD_BYTES: usize = 512;

fn counter(name: &str) -> u64 {
    fs::read_to_string(format!("/sys/class/net/lo/statistics/{name}"))
        .unwrap()
        .trim()
        .parse()
        .unwrap()
}

fn rss_bytes() -> u64 {
    let status = fs::read_to_string("/proc/self/status").unwrap();
    status
        .lines()
        .find(|line| line.starts_with("VmRSS:"))
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse::<u64>()
        .unwrap()
        * 1024
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .with_writer(std::io::stderr)
        .try_init();
    let mode = std::env::args_os().nth(1).ok_or("direct or gossip")?;
    let mode = mode.to_str().ok_or("mode must be UTF-8")?;
    if mode != "direct" && mode != "gossip" {
        return Err("direct or gossip".into());
    }
    let workspace = [37; 32];
    let topic = Topic::new("streams/measure").unwrap();
    let mut nodes = Vec::new();
    let mut receivers = Vec::new();
    for _ in 0..PARTICIPANTS {
        let (node, receiver) = Node::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        nodes.push(node);
        receivers.push(receiver);
    }
    let addresses = nodes
        .iter()
        .map(|node| (node.id(), node.address()))
        .collect::<Vec<_>>();
    let mut policy = BTreeMap::new();
    policy.insert(
        nodes[0].id(),
        Permissions::Selected {
            publish: BTreeSet::from([topic.clone()]),
            subscribe: BTreeSet::new(),
        },
    );
    for node in &nodes[1..] {
        policy.insert(
            node.id(),
            Permissions::Selected {
                publish: BTreeSet::new(),
                subscribe: BTreeSet::from([topic.clone()]),
            },
        );
    }
    for node in &nodes {
        node.install_verified_policy(workspace, 1, policy.clone())
            .await
            .unwrap();
        for (peer, address) in &addresses {
            if *peer != node.id() {
                node.add_address_hint(*peer, *address).await.unwrap();
            }
        }
    }
    for node in &nodes[1..] {
        let report = node.subscribe(workspace, 1, topic.clone()).await.unwrap();
        assert_eq!(report.admitted, vec![nodes[0].id()]);
        assert!(report.failed.is_empty());
    }
    if mode == "gossip" {
        for node in &nodes {
            node.enable_gossip(workspace, 1).await.unwrap();
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let counts = futures_util::future::join_all(
                nodes.iter().map(|node| node.live_neighbor_count(workspace)),
            )
            .await;
            if counts.iter().all(|count| *count > 0) {
                break;
            }
            assert!(Instant::now() < deadline, "gossip did not form");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
    tokio::time::sleep(Duration::from_secs(if mode == "gossip" { 3 } else { 0 })).await;
    let neighbor_counts = futures_util::future::join_all(
        nodes.iter().map(|node| node.live_neighbor_count(workspace)),
    )
    .await;
    let idle_before = counter("tx_bytes");
    tokio::time::sleep(Duration::from_millis(250)).await;
    let idle_wire_bytes = counter("tx_bytes") - idle_before;
    let tx_before = counter("tx_bytes");
    let rx_before = counter("rx_bytes");
    let rss_before = rss_bytes();
    let started = Instant::now();
    let publisher = nodes[0].id();
    let receive_tasks = receivers
        .into_iter()
        .skip(1)
        .enumerate()
        .map(|(index, mut receiver)| {
            let topic = topic.clone();
            tokio::spawn(async move {
                let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
                let mut seen = BTreeSet::new();
                let mut latencies = Vec::new();
                let mut duplicates = 0usize;
                while seen.len() < PUBLICATIONS {
                    let Ok(Some(message)) =
                        tokio::time::timeout_at(deadline, receiver.recv()).await
                    else {
                        break;
                    };
                    assert_eq!(message.sender, publisher);
                    assert_eq!(message.workspace, workspace);
                    assert_eq!(message.topic, topic);
                    let sequence = u64::from_be_bytes(message.payload[..8].try_into().unwrap());
                    let sent_ns = u64::from_be_bytes(message.payload[8..16].try_into().unwrap());
                    if seen.insert(sequence) {
                        latencies.push((started.elapsed().as_nanos() as u64 - sent_ns) / 1_000);
                    } else {
                        duplicates += 1;
                    }
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
                while let Ok(message) = receiver.try_recv() {
                    let sequence = u64::from_be_bytes(message.payload[..8].try_into().unwrap());
                    if !seen.insert(sequence) {
                        duplicates += 1;
                    }
                }
                (index + 1, seen.len(), duplicates, latencies)
            })
        })
        .collect::<Vec<_>>();
    let mut remote_admissions = 0usize;
    let mut queued = 0usize;
    for sequence in 0..PUBLICATIONS {
        let mut payload = vec![sequence as u8; PAYLOAD_BYTES];
        payload[..8].copy_from_slice(&(sequence as u64).to_be_bytes());
        payload[8..16].copy_from_slice(&(started.elapsed().as_nanos() as u64).to_be_bytes());
        let report = nodes[0]
            .publish(workspace, 1, topic.clone(), payload)
            .await
            .unwrap();
        assert!(report.failed.is_empty());
        remote_admissions += report
            .admitted
            .iter()
            .filter(|peer| **peer != nodes[0].id())
            .count();
        queued += usize::from(report.queued);
    }
    let mut received = 0usize;
    let mut duplicates = 0usize;
    let mut latencies = Vec::new();
    let mut received_by_node = vec![0usize; PARTICIPANTS];
    for task in receive_tasks {
        let (index, count, repeated, mut measured) = task.await.unwrap();
        received_by_node[index] = count;
        received += count;
        duplicates += repeated;
        latencies.append(&mut measured);
    }
    let elapsed = started.elapsed();
    latencies.sort_unstable();
    let p95 = latencies
        .get((latencies.len() * 95 / 100).min(latencies.len().saturating_sub(1)))
        .copied()
        .unwrap_or(u64::MAX);
    let result = json!({
        "passed": duplicates == 0 && received == PUBLICATIONS * (PARTICIPANTS - 1) && p95 <= 2_000_000,
        "scope": "one Linux process, independent Iroh endpoints, host loopback, injected routing policy; no MLS, ATAK, WAN or Android capacity claim",
        "mode": mode,
        "iroh_gossip": "0.101.0",
        "endpoint_ids": addresses.iter().map(|(id, _)| iroh::EndpointId::from_bytes(id).unwrap().to_string()).collect::<Vec<_>>(),
        "participants": PARTICIPANTS,
        "publications": PUBLICATIONS,
        "payload_bytes": PAYLOAD_BYTES,
        "expected_deliveries": PUBLICATIONS * (PARTICIPANTS - 1),
        "received": received,
        "received_by_node": received_by_node,
        "duplicates": duplicates,
        "elapsed_ms": elapsed.as_millis(),
        "latency_us": {
            "median": latencies.get(latencies.len() / 2),
            "p95": if p95 == u64::MAX { None } else { Some(p95) },
            "max": latencies.last()
        },
        "loopback_wire_bytes": {
            "tx": counter("tx_bytes") - tx_before,
            "rx": counter("rx_bytes") - rx_before,
            "idle_tx_during_250_ms_before_load": idle_wire_bytes,
            "boundary": "System-wide Linux loopback counters with no concurrent Arachne workload; includes QUIC acknowledgements, Gossip control and any unrelated host-loopback traffic during the measured window"
        },
        "connections": {
            "maintained_overlay_neighbors_by_node": neighbor_counts,
            "maintained_overlay_neighbor_sum": neighbor_counts.iter().sum::<usize>(),
            "maintained_overlay_neighbor_max": neighbor_counts.iter().copied().max(),
            "confirmed_remote_direct_admissions": remote_admissions,
            "local_overlay_queue_admissions": queued
        },
        "process_rss_bytes": {"before": rss_before, "after": rss_bytes()},
        "limits": "Closed-loop functional comparison. Direct admissions count acknowledged per-recipient operations, not stable QUIC paths. Interface bytes are measured; payload confidentiality and Android resource use are covered separately."
    });
    println!("{}", serde_json::to_string_pretty(&result).unwrap());
    for node in nodes.into_iter().rev() {
        node.close().await;
    }
    Ok(())
}
