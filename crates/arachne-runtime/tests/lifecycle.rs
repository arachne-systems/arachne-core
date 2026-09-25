//! ADR step 4: lifecycle calls from any thread, per-op deadlines, one event
//! pull over every queue, and suspend/resume. Each test owns its context.
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use arachne_runtime::{
    Client, ClientConfig, Context, ContextConfig, ErrorCode, Network, TransportOptions,
    TransportTimeouts,
};

fn context() -> Arc<Context> {
    Context::new(ContextConfig::default()).unwrap()
}

fn direct(secret: Option<[u8; 32]>) -> ClientConfig {
    ClientConfig {
        network: Network::Direct,
        secret,
        transport: Default::default(),
    }
}

fn local(client: &Client) -> String {
    client
        .endpoint()
        .unwrap()
        .bound_address
        .replace("0.0.0.0:", "127.0.0.1:")
}

#[test]
fn close_from_another_thread_releases_a_parked_waiter() {
    let context = context();
    let client = Arc::new(context.open(direct(None)).unwrap());
    let parked = Arc::clone(&client);
    // The long timeout makes the test fail if close does not wake the waiter.
    let waiter = thread::spawn(move || parked.wait_for_work(Some(Duration::from_secs(30))));
    thread::sleep(Duration::from_millis(200));
    let closing = Instant::now();
    client.close().unwrap();
    assert!(!waiter.join().unwrap().unwrap());
    let elapsed = closing.elapsed();
    assert!(elapsed < Duration::from_secs(2), "waiter took {elapsed:?}");
    // Close is idempotent; later calls fail with Closed (code 1).
    client.close().unwrap();
    let error = client.wait_for_work(Some(Duration::ZERO)).unwrap_err();
    assert_eq!(error.code(), ErrorCode::Closed);
    assert_eq!(client.endpoint().unwrap_err().code(), ErrorCode::Closed);
}

#[test]
fn wake_releases_a_waiter_and_a_timeout_returns() {
    let context = context();
    let client = Arc::new(context.open(direct(None)).unwrap());
    let started = Instant::now();
    assert!(!client.wait_for_work(Some(Duration::from_millis(100))).unwrap());
    assert!(started.elapsed() >= Duration::from_millis(100));
    let parked = Arc::clone(&client);
    let waiter = thread::spawn(move || parked.wait_for_work(Some(Duration::from_secs(30))));
    thread::sleep(Duration::from_millis(100));
    let woken = Instant::now();
    client.wake().unwrap();
    assert!(!waiter.join().unwrap().unwrap());
    assert!(woken.elapsed() < Duration::from_secs(2));
    // The session is still open.
    client.endpoint().unwrap();
}

#[test]
fn a_per_op_deadline_fails_the_op_and_keeps_the_session() {
    let context = context();
    // A peer that is gone: its port is closed, so a dial waits out its timeout.
    let gone = context.open(direct(None)).unwrap();
    let peer = gone.endpoint().unwrap().endpoint_key;
    let address = local(&gone);
    gone.close().unwrap();

    let client = context
        .open(ClientConfig {
            network: Network::Direct,
            secret: Some([61; 32]),
            transport: TransportOptions {
                timeouts: Some(TransportTimeouts {
                    operation: Duration::from_secs(30),
                    dial: Duration::from_secs(30),
                    gossip_join: Duration::from_secs(30),
                    close_drain: Duration::from_secs(1),
                }),
                ..Default::default()
            },
        })
        .unwrap()
        .with_deadline(Duration::from_millis(300));
    client.add_address_hint(peer, &address).unwrap();
    for _ in 0..2 {
        // Twice: a deadline must not leave the session cancelled.
        let started = Instant::now();
        let error = client.send_nearby_invitation(peer, &[7; 16]).unwrap_err();
        let elapsed = started.elapsed();
        assert_eq!(error.code(), ErrorCode::DeadlineExceeded, "{error}");
        assert!(elapsed >= Duration::from_millis(250), "failed at once: {elapsed:?}");
        assert!(elapsed < Duration::from_secs(5), "deadline ignored: {elapsed:?}");
    }
    // An explicit cancel is not sticky either.
    client.cancel().unwrap();
    client.set_deadline(None);
    client.endpoint().unwrap();
    client.workspace_state().unwrap();
    let started = Instant::now();
    client.set_deadline(Some(Duration::from_millis(300)));
    let error = client.send_nearby_invitation(peer, &[7; 16]).unwrap_err();
    assert_eq!(error.code(), ErrorCode::DeadlineExceeded, "{error}");
    assert!(started.elapsed() >= Duration::from_millis(250));
}
