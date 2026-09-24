// Closing a session must not fail because a peer's link is slow.
//
// `close` asks the transport to drain: every open connection sends a close
// frame and waits for it to be acknowledged. The transport bounds that wait at
// three probe timeouts (PTO) of the slowest open connection, and a PTO grows
// with the round trip time it measured (smoothed RTT plus four times its
// variance). A slow link, such as Tor, or a CPU-starved host where the loopback
// RTT reaches seconds, therefore makes the drain take longer than any fixed
// deadline. The drain is best effort: a peer that misses the close frame learns
// of it by its own idle timeout. So an overrun must end the drain, not fail the
// close.
//
// This test puts a UDP delay relay between a peer and the owner, so that the
// owner measures a round trip time of about 2 s. The drain then needs at least
// 3 x 2 s = 6 s, since a PTO is never less than the smoothed RTT. The owner's
// close drain deadline is 3 s, so close must end before the drain would. Its
// operation deadline is 60 s, so a close that followed the operation deadline
// instead would wait for the whole drain.

use arachne_node::{ConnectionBudget, NetworkProfile, Node, NodeOptions, Timeouts};
use arachne_runtime::{close, create_with_options, describe, wait_for_work};
use serde_json::Value;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

/// Delay added in each direction; the owner measures about twice this.
const ONE_WAY_DELAY: Duration = Duration::from_millis(1000);

/// The owner's close drain deadline.
const OWNER_CLOSE_DRAIN: Duration = Duration::from_secs(3);

/// Forward UDP datagrams between one client and `server`, each after
/// `ONE_WAY_DELAY`. The client is the first address that is not `server`.
async fn delay_relay(server: SocketAddr) -> SocketAddr {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let address = socket.local_addr().unwrap();
    let client: Arc<Mutex<Option<SocketAddr>>> = Arc::default();
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 65_536];
        loop {
            let Ok((length, from)) = socket.recv_from(&mut buffer).await else {
                return;
            };
            let target = if from == server {
                match *client.lock().unwrap() {
                    Some(client) => client,
                    None => continue,
                }
            } else {
                *client.lock().unwrap() = Some(from);
                server
            };
            let datagram = buffer[..length].to_vec();
            let socket = Arc::clone(&socket);
            tokio::spawn(async move {
                tokio::time::sleep(ONE_WAY_DELAY).await;
                let _ = socket.send_to(&datagram, target).await;
            });
        }
    });
    address
}

#[test]
fn close_succeeds_when_the_drain_outlasts_the_close_drain_deadline() {
    let mut owner_options = NodeOptions::new(NetworkProfile::Direct);
    owner_options.timeouts.operation = Duration::from_secs(60);
    owner_options.timeouts.close_drain = OWNER_CLOSE_DRAIN;
    let owner = create_with_options(None, owner_options).unwrap();
    let info: Value = serde_json::from_str(&describe(owner).unwrap()).unwrap();
    let owner_peer: [u8; 32] = info["endpoint_key"]
        .as_array()
        .unwrap()
        .iter()
        .map(|byte| byte.as_u64().unwrap() as u8)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let owner_port: u16 = info["bound_address"]
        .as_str()
        .unwrap()
        .rsplit_once(':')
        .unwrap()
        .1
        .parse()
        .unwrap();
    let owner_address = SocketAddr::from(([127, 0, 0, 1], owner_port));

    // The peer lives on its own runtime. Dropping that runtime makes the peer
    // vanish without a close, as a peer that loses power or network does.
    let peer_runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    peer_runtime.block_on(async {
        let relay = delay_relay(owner_address).await;
        // The peer's own deadlines must cover a 2 s round trip.
        let mut options = NodeOptions::new(NetworkProfile::Direct);
        options.timeouts = Timeouts {
            operation: Duration::from_secs(60),
            dial: Duration::from_secs(60),
            gossip_join: Duration::from_secs(60),
            close_drain: Duration::from_secs(60),
        };
        let (peer, _) = Node::bind_with_options(
            "127.0.0.1:0".parse().unwrap(),
            None,
            options,
            ConnectionBudget::default(),
        )
        .await
        .unwrap();
        peer.add_address_hint(owner_peer, relay).await.unwrap();
        // The owner never answers. The request only has to open the link.
        tokio::spawn(async move {
            let _ = peer.request_control(owner_peer, b"open the link").await;
            drop(peer);
        });
    });
    // The owner's control signal fires once the request crossed the link, so
    // the owner holds an open connection with RTT samples near 2 s.
    let arrived = thread::spawn(move || wait_for_work(owner));
    let deadline = Instant::now() + Duration::from_secs(60);
    while !arrived.is_finished() {
        assert!(
            Instant::now() < deadline,
            "the request never reached the owner"
        );
        thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(arrived.join().unwrap(), Ok(true));
    peer_runtime.shutdown_background();

    let started = Instant::now();
    let closed = close(owner);
    let elapsed = started.elapsed();
    assert_eq!(
        closed,
        Ok(()),
        "a slow drain must not fail close (took {elapsed:?})"
    );
    // The drain follows the owner's close drain deadline (3 s), not the
    // transport's 3 x PTO (at least 6 s here) and not the operation deadline.
    assert!(
        elapsed < Duration::from_secs(5),
        "close must follow the close drain deadline ({OWNER_CLOSE_DRAIN:?}), took {elapsed:?}"
    );
    println!("close_drain: close took {elapsed:?}");
}
