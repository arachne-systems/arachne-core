//! ADR step 3: an owned `Context` replaces the process-wide registry.
//! Each test makes its own contexts, so these tests run in parallel.
use std::time::{Duration, Instant};

use arachne_runtime::{ClientConfig, Context, ContextConfig, ErrorCode, Limits, Network};

fn config() -> ClientConfig {
    ClientConfig {
        network: Network::Direct,
        secret: None,
        transport: Default::default(),
        storage: None,
    }
}

fn context(max_sessions: u32) -> std::sync::Arc<Context> {
    Context::new(
        ContextConfig::default().with_limits(Limits::default().with_max_sessions(max_sessions)),
    )
    .unwrap()
}

#[test]
fn two_contexts_in_one_process_are_independent() {
    let first = context(1);
    let second = context(1);
    let mut a = first.open(config()).unwrap();
    // The cap of one context does not count the other context's sessions.
    let b = second.open(config()).unwrap();
    let refused = first.open(config()).err().expect("first context is full");
    assert_eq!(refused.code(), ErrorCode::LimitReached);
    assert_eq!(first.session_count(), 1);
    assert_eq!(second.session_count(), 1);
    // Closing in one context leaves the other context's session live.
    a.close().unwrap();
    assert_eq!(first.session_count(), 0);
    b.endpoint().unwrap();
    first.open(config()).unwrap();
}

#[test]
fn more_than_eight_sessions_work_when_the_limit_allows() {
    let context = context(12);
    let clients: Vec<_> = (0..12).map(|_| context.open(config()).unwrap()).collect();
    for client in &clients {
        client.endpoint().unwrap();
    }
    assert_eq!(context.session_count(), 12);
    let refused = context.open(config()).err().expect("limit is twelve");
    assert_eq!(refused.code(), ErrorCode::LimitReached);
}

#[test]
fn clients_share_one_runtime_and_close_leaves_no_tasks() {
    let context = context(4);
    let baseline = context.alive_tasks();
    let clients: Vec<_> = (0..3).map(|_| context.open(config()).unwrap()).collect();
    assert!(context.alive_tasks() > baseline);
    for mut client in clients {
        client.close().unwrap();
    }
    // Tasks end when their session closes, not when a runtime shuts down.
    let deadline = Instant::now() + Duration::from_secs(7);
    while context.alive_tasks() > baseline && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(context.alive_tasks(), baseline, "tasks leaked after close");
}

#[test]
fn a_host_runtime_handle_must_be_multi_thread() {
    let host = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let refused = Context::new(
        ContextConfig::default()
            .with_runtime(arachne_runtime::RuntimeConfig::Handle(host.handle().clone())),
    )
    .err()
    .expect("a current-thread runtime cannot drive blocking calls");
    assert_eq!(refused.code(), ErrorCode::InvalidInput);

    let host = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    let context = Context::new(
        ContextConfig::default()
            .with_runtime(arachne_runtime::RuntimeConfig::Handle(host.handle().clone())),
    )
    .unwrap();
    let mut client = context.open(config()).unwrap();
    client.endpoint().unwrap();
    client.close().unwrap();
}
