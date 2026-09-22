use std::time::Duration;

use arachne_node::Node;

fn rss_kib() -> usize {
    std::fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))
        .and_then(|value| value.trim().trim_end_matches("kB").trim().parse().ok())
        .unwrap()
}

/// How much memory an open control connection costs, both ends counted. The
/// tablet owner held about 500 of them in a 500-joiner run with 264 MB free
/// (HEWN, 2026-09-19). Run: cargo test --release -p arachne-node --test
/// connection_memory -- --ignored --nocapture
#[test]
#[ignore = "memory measurement; prints numbers"]
fn memory_per_open_control_connection() {
    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
    runtime.block_on(async {
        const CLIENTS: usize = 200;
        let (mut server, _) = Node::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let mut clients = Vec::new();
        for _ in 0..CLIENTS {
            let (client, _) = Node::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
            client.add_address_hint(server.id(), server.address()).await.unwrap();
            clients.push(client);
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
        let bound = rss_kib();
        let mut pending = Vec::new();
        for client in &clients {
            pending.push(tokio::spawn(client.request_control(server.id(), b"hold")));
        }
        let mut served = 0;
        while served < CLIENTS {
            if let Some(request) = server.poll_control() {
                request.respond(vec![1]).unwrap();
                served += 1;
            } else {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
        for task in pending {
            task.await.unwrap().unwrap();
        }
        // Connections stay open and idle, as on the owner between queries.
        tokio::time::sleep(Duration::from_secs(3)).await;
        let connected = rss_kib();
        eprintln!(
            "nodes={} rss_bound={} KiB rss_connected={} KiB per_connection_both_ends={} KiB per_node={} KiB",
            CLIENTS + 1,
            bound,
            connected,
            (connected - bound) / CLIENTS,
            bound / (CLIENTS + 1)
        );
    });
}
