//! Measured direct-Iroh fixture, not secure onboarding or a field-scale claim.
use arachne_node::{Node, Permissions, Topic};
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    time::{Duration, Instant},
};

async fn run() -> Result<serde_json::Value, Box<dyn Error>> {
    let args: Vec<_> = std::env::args_os()
        .skip(1)
        .map(|arg| arg.into_string().map_err(|_| "arguments must be UTF-8"))
        .collect::<Result<_, _>>()?;
    if args.len() != 3 {
        return Err("usage: load PARTICIPANTS PUBLICATIONS PAYLOAD_BYTES".into());
    }
    let participants: usize = args[0].parse()?;
    let publications: usize = args[1].parse()?;
    let size: usize = args[2].parse()?;
    if !(2..=1000).contains(&participants)
        || !(1..=10000).contains(&publications)
        || !(16..=16384).contains(&size)
        || participants * publications > 1_000_000
    {
        return Err("bounded run requires 2..1000 participants, 1..10000 publications, 16..16384 bytes, <=1000000 deliveries".into());
    }
    let origin = Instant::now();
    let (publisher, _unused) = Node::bind("127.0.0.1:0".parse()?).await?;
    let topic = Topic::new("streams/load")?;
    let mut sinks = Vec::new();
    let mut receivers = Vec::new();
    let mut policy = BTreeMap::from([(
        publisher.id(),
        Permissions::Selected {
            publish: BTreeSet::from([topic.clone()]),
            subscribe: BTreeSet::new(),
        },
    )]);
    for _ in 1..participants {
        let (node, receiver) = Node::bind("127.0.0.1:0".parse()?).await?;
        publisher
            .add_address_hint(node.id(), node.address())
            .await?;
        node.add_address_hint(publisher.id(), publisher.address())
            .await?;
        policy.insert(
            node.id(),
            Permissions::Selected {
                publish: BTreeSet::new(),
                subscribe: BTreeSet::from([topic.clone()]),
            },
        );
        sinks.push(node);
        receivers.push(receiver);
    }
    for node in std::iter::once(&publisher).chain(sinks.iter()) {
        for workspace in [[1; 32], [2; 32]] {
            node.install_verified_policy(workspace, 1, policy.clone())
                .await?;
        }
    }
    for node in &sinks {
        let report = node.subscribe([1; 32], 1, topic.clone()).await?;
        if report.admitted != vec![publisher.id()] || !report.failed.is_empty() {
            return Err(format!("subscription failed: {report:?}").into());
        }
    }
    let mut consumers = Vec::new();
    for mut receiver in receivers {
        let sender = publisher.id();
        let topic = topic.clone();
        consumers.push(tokio::spawn(async move {
            let mut seen = BTreeSet::new();
            let mut latencies = Vec::new();
            let mut invalid = 0;
            let mut duplicates = 0;
            while let Some(message) = receiver.recv().await {
                if message.sender != sender
                    || message.workspace != [1; 32]
                    || message.revision != 1
                    || message.topic != topic
                    || message.payload.len() != size
                {
                    invalid += 1;
                    continue;
                }
                let sequence = u64::from_le_bytes(message.payload[..8].try_into().unwrap());
                let sent = u64::from_le_bytes(message.payload[8..16].try_into().unwrap());
                let now = origin.elapsed().as_micros() as u64;
                if sequence >= publications as u64
                    || sent > now
                    || message.payload[16..].iter().any(|v| *v != 0xa5)
                {
                    invalid += 1;
                    continue;
                }
                if !seen.insert(sequence) {
                    duplicates += 1;
                } else {
                    latencies.push(now - sent);
                }
            }
            (latencies, invalid, duplicates)
        }));
    }
    let started = Instant::now();
    let mut admitted = 0;
    let mut rejected = 0;
    // ponytail: saturated serial producer measures current fanout; add paced/concurrent load when comparing scheduling changes.
    for sequence in 0..publications {
        let mut payload = vec![0xa5; size];
        payload[..8].copy_from_slice(&(sequence as u64).to_le_bytes());
        payload[8..16].copy_from_slice(&(origin.elapsed().as_micros() as u64).to_le_bytes());
        let report = publisher
            .publish([1; 32], 1, topic.clone(), payload)
            .await?;
        admitted += report.admitted.len();
        rejected += report.failed.len();
    }
    let publishing_seconds = started.elapsed().as_secs_f64();
    let isolated = publisher
        .publish([2; 32], 1, topic.clone(), vec![0; size])
        .await?;
    let isolation_passed = isolated.admitted.is_empty() && isolated.failed.is_empty();
    for node in &sinks {
        let report = node.unsubscribe([1; 32], 1, topic.clone()).await?;
        if report.admitted != vec![publisher.id()] || !report.failed.is_empty() {
            return Err(format!("unsubscribe failed: {report:?}").into());
        }
    }
    let unsubscribed = publisher.publish([1; 32], 1, topic, vec![0; size]).await?;
    let unsubscribe_passed = unsubscribed.admitted.is_empty() && unsubscribed.failed.is_empty();
    for node in sinks {
        node.close().await;
    }
    publisher.close().await;
    let mut latency = Vec::new();
    let mut invalid = 0;
    let mut duplicates = 0;
    for consumer in consumers {
        let (times, bad, repeated) = consumer.await?;
        latency.extend(times);
        invalid += bad;
        duplicates += repeated;
    }
    latency.sort_unstable();
    let expected = (participants - 1) * publications;
    let percentile = |p: usize| {
        latency
            .get((latency.len() * p).div_ceil(100).saturating_sub(1))
            .copied()
    };
    Ok(serde_json::json!({
        "scope": "single-process independent Iroh endpoints; loopback; injected authorization; no MLS or ATAK",
        "participants": participants, "publications": publications, "payload_bytes": size,
        "load": "saturated sequential publish", "publishing_seconds": publishing_seconds,
        "expected_deliveries": expected, "queue_admissions": admitted, "failed_admissions": rejected,
        "consumer_received_unique": latency.len(), "missing_deliveries": expected.saturating_sub(latency.len()),
        "duplicates": duplicates, "invalid": invalid,
        "consumer_latency_us": {"p50":percentile(50),"p95":percentile(95),"p99":percentile(99)},
        "latency_clock": "shared monotonic Instant; publish start to consumer receive",
        "publication_rate_per_second": publications as f64 / publishing_seconds,
        "payload_delivery_bytes_per_second": latency.len() as f64 * size as f64 / publishing_seconds,
        "wire_bandwidth_measured": false, "cpu_memory_measured": false,
        "isolation_passed": isolation_passed, "unsubscribe_passed": unsubscribe_passed,
        "passed": latency.len() == expected && admitted == expected && rejected == 0 && invalid == 0
            && duplicates == 0 && isolation_passed && unsubscribe_passed
    }))
}

#[tokio::main]
async fn main() {
    let result = match tokio::time::timeout(Duration::from_secs(180), run()).await {
        Ok(Ok(value)) => value,
        Ok(Err(error)) => serde_json::json!({"passed":false,"error":error.to_string()}),
        Err(_) => serde_json::json!({"passed":false,"error":"180 second run deadline"}),
    };
    println!("{}", serde_json::to_string_pretty(&result).unwrap());
    if result["passed"] != true {
        std::process::exit(1);
    }
}
