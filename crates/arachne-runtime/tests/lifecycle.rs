//! ADR step 4: lifecycle calls from any thread, per-op deadlines, one event
//! pull over every queue, and suspend/resume. Each test owns its context.
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use arachne_runtime::{
    Client, ClientConfig, Context, ContextConfig, ErrorCode, Event, Network, PeerPolicy,
    PowerProfile, TransportOptions, TransportTimeouts,
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

#[test]
fn close_from_another_thread_releases_a_parked_next_event() {
    let context = context();
    let client = Arc::new(context.open(direct(None)).unwrap());
    let parked = Arc::clone(&client);
    let waiter = thread::spawn(move || parked.next_event(Some(Duration::from_secs(30))));
    thread::sleep(Duration::from_millis(200));
    let closing = Instant::now();
    client.close().unwrap();
    assert_eq!(waiter.join().unwrap().unwrap(), None);
    assert!(closing.elapsed() < Duration::from_secs(2));
    let error = client.next_event(Some(Duration::ZERO)).unwrap_err();
    assert_eq!(error.code(), ErrorCode::Closed);
}

#[test]
fn next_event_times_out_and_wakes_with_none() {
    let context = context();
    let client = Arc::new(context.open(direct(None)).unwrap());
    let started = Instant::now();
    assert_eq!(client.next_event(Some(Duration::from_millis(100))).unwrap(), None);
    assert!(started.elapsed() >= Duration::from_millis(100));
    let parked = Arc::clone(&client);
    let waiter = thread::spawn(move || parked.next_event(Some(Duration::from_secs(30))));
    thread::sleep(Duration::from_millis(100));
    client.wake().unwrap();
    assert_eq!(waiter.join().unwrap().unwrap(), None);
}

#[test]
fn next_event_reports_a_control_request() {
    let context = context();
    let owner = context.open(direct(Some([81; 32]))).unwrap();
    owner.create_workspace("Event owner", Some("Events")).unwrap();
    let peer = owner.endpoint().unwrap().endpoint_key;
    let address: std::net::SocketAddr = local(&owner).parse().unwrap();
    let sender = thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let (node, _) = arachne_node::Node::bind("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap();
            node.add_address_hint(peer, address).await.unwrap();
            node.request_control(peer, b"DFND\x01").await.unwrap()
        })
    });
    assert_eq!(
        owner.next_event(Some(Duration::from_secs(10))).unwrap(),
        Some(Event::Control)
    );
    assert!(owner.poll_control().unwrap());
    sender.join().unwrap();
    assert_eq!(owner.next_event(Some(Duration::from_millis(100))).unwrap(), None);
}

/// A fixture publisher and subscriber with routes both ways and the
/// subscriber's interest announced (not yet observed).
fn pubsub(context: &Arc<Context>, seed: u8) -> (Client, Client, [u8; 32], &'static str) {
    let publisher = context.open(direct(Some([seed; 32]))).unwrap();
    let subscriber = context.open(direct(Some([seed + 1; 32]))).unwrap();
    let publisher_key = publisher.endpoint().unwrap().endpoint_key;
    let subscriber_key = subscriber.endpoint().unwrap().endpoint_key;
    let workspace = [seed + 2; 32];
    let topic = "streams/events";
    let policy = [
        PeerPolicy {
            peer: publisher_key,
            publish: vec![topic.into()],
            subscribe: Vec::new(),
        },
        PeerPolicy {
            peer: subscriber_key,
            publish: Vec::new(),
            subscribe: vec![topic.into()],
        },
    ];
    publisher
        .add_address_hint(subscriber_key, &local(&subscriber))
        .unwrap();
    subscriber
        .add_address_hint(publisher_key, &local(&publisher))
        .unwrap();
    publisher.install_policy(workspace, 1, &policy).unwrap();
    subscriber.install_policy(workspace, 1, &policy).unwrap();
    subscriber.set_interest(workspace, 1, topic, true).unwrap();
    (publisher, subscriber, workspace, topic)
}

#[test]
fn next_event_reports_interest_and_publication() {
    let context = context();
    let (publisher, subscriber, workspace, topic) = pubsub(&context, 71);

    // `set_interest` starts the announcement in the background; its end is
    // an event, and `poll_interest` reads its result.
    assert_eq!(
        subscriber.next_event(Some(Duration::from_secs(10))).unwrap(),
        Some(Event::InterestChanged)
    );
    let observation = subscriber.poll_interest().unwrap().expect("interest result");
    assert!(observation.admission.failed.is_empty());
    // A ready job reports once.
    assert_eq!(subscriber.next_event(Some(Duration::from_millis(200))).unwrap(), None);

    publisher.publish(workspace, 1, topic, vec![1, 2, 3]).unwrap();
    assert_eq!(
        subscriber.next_event(Some(Duration::from_secs(10))).unwrap(),
        Some(Event::PublicationReceived)
    );
    // A queue reports until it is drained.
    assert_eq!(
        subscriber.next_event(Some(Duration::ZERO)).unwrap(),
        Some(Event::PublicationReceived)
    );
    assert_eq!(subscriber.poll().unwrap().unwrap().payload, vec![1, 2, 3]);
    assert_eq!(subscriber.next_event(Some(Duration::from_millis(100))).unwrap(), None);

    // A network change queues an interest repair. A host that only waits on
    // next_event must hear of it, so the repair starts at its poll.
    subscriber.network_change().unwrap();
    assert_eq!(
        subscriber.next_event(Some(Duration::from_secs(2))).unwrap(),
        Some(Event::InterestChanged)
    );
    // The poll starts the repair; its end is the next event.
    let _ = subscriber.poll_interest().unwrap();
    assert_eq!(
        subscriber.next_event(Some(Duration::from_secs(10))).unwrap(),
        Some(Event::InterestChanged)
    );
    assert!(subscriber.poll_interest().unwrap().is_some());
}

#[test]
fn suspend_stops_background_timers_and_resume_restores_them() {
    let context = context();
    let owner = context.open(direct(Some([91; 32]))).unwrap();
    let info = owner.create_workspace("Suspend owner", Some("Suspend")).unwrap();
    owner.install_workspace_policy(info.epoch + 1).unwrap();
    assert_eq!(context.background_timers(), 1, "one gossip overlay");

    context.suspend().unwrap();
    assert!(context.is_suspended());
    assert_eq!(context.background_timers(), 0);
    // State stays and ops still run.
    assert!(owner.workspace_state().unwrap().workspace_ready);
    // A session opened while suspended starts suspended; its policy
    // install parks its overlay.
    let late = context.open(direct(Some([92; 32]))).unwrap();
    let late_info = late.create_workspace("Late owner", None).unwrap();
    late.install_workspace_policy(late_info.epoch + 1).unwrap();
    assert_eq!(context.background_timers(), 0);
    context.suspend().unwrap();

    context.resume().unwrap();
    assert!(!context.is_suspended());
    assert_eq!(context.background_timers(), 2);
    context.resume().unwrap();
    assert_eq!(context.background_timers(), 2);
}

#[test]
fn contexts_suspend_independently() {
    let first = context();
    let second = context();
    let a = first.open(direct(Some([93; 32]))).unwrap();
    let b = second.open(direct(Some([94; 32]))).unwrap();
    for client in [&a, &b] {
        let info = client.create_workspace("Owner", None).unwrap();
        client.install_workspace_policy(info.epoch + 1).unwrap();
    }
    first.suspend().unwrap();
    assert_eq!(first.background_timers(), 0);
    assert_eq!(second.background_timers(), 1);
    assert!(!second.is_suspended());
}

#[test]
fn low_power_lengthens_the_presence_interval() {
    let normal = context();
    let low = Context::new(ContextConfig::default().with_power(PowerProfile::Low)).unwrap();
    assert_eq!(low.power(), PowerProfile::Low);
    assert_eq!(normal.power(), PowerProfile::Normal);
    assert!(low.presence_interval() > normal.presence_interval());
}

#[test]
fn close_while_another_thread_is_inside_an_op_is_bounded() {
    let context = context();
    let gone = context.open(direct(None)).unwrap();
    let peer = gone.endpoint().unwrap().endpoint_key;
    let address = local(&gone);
    gone.close().unwrap();
    let client = Arc::new(
        context
            .open(ClientConfig {
                network: Network::Direct,
                secret: Some([62; 32]),
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
            .unwrap(),
    );
    client.add_address_hint(peer, &address).unwrap();
    let busy = Arc::clone(&client);
    // No deadline: only close can end this 30 s dial early.
    let op = thread::spawn(move || {
        let started = Instant::now();
        let result = busy.send_nearby_invitation(peer, &[7; 16]);
        (result, started.elapsed())
    });
    thread::sleep(Duration::from_millis(300));
    let closing = Instant::now();
    client.close().unwrap();
    let closed_in = closing.elapsed();
    let (result, op_time) = op.join().unwrap();
    assert!(result.is_err());
    // Close drain (1 s) plus the local teardown (2 s) bound it.
    assert!(closed_in < Duration::from_millis(3500), "close took {closed_in:?}");
    assert!(op_time < Duration::from_secs(4), "op ran {op_time:?}");
}

#[test]
fn suspend_closes_idle_connections_and_resume_reconnects() {
    let context = context();
    let (publisher, subscriber, workspace, topic) = pubsub(&context, 101);
    assert_eq!(
        subscriber.next_event(Some(Duration::from_secs(10))).unwrap(),
        Some(Event::InterestChanged)
    );
    assert!(subscriber.poll_interest().unwrap().unwrap().admission.failed.is_empty());
    publisher.publish(workspace, 1, topic, vec![1]).unwrap();
    assert!(context.open_connections() > 0, "the publication opened a link");
    let address = publisher.endpoint().unwrap().bound_address;

    context.suspend().unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    while context.open_connections() > 0 && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(context.open_connections(), 0, "idle links stay open while suspended");
    // The endpoint stays bound.
    assert_eq!(publisher.endpoint().unwrap().bound_address, address);
    // Queued data stays too.
    assert_eq!(subscriber.poll().unwrap().unwrap().payload, vec![1]);

    context.resume().unwrap();
    let report = publisher.publish(workspace, 1, topic, vec![2]).unwrap();
    assert!(report.failed.is_empty(), "{report:?}");
    assert_eq!(
        subscriber.next_event(Some(Duration::from_secs(10))).unwrap(),
        Some(Event::PublicationReceived)
    );
    assert_eq!(subscriber.poll().unwrap().unwrap().payload, vec![2]);
    assert!(context.open_connections() > 0);
}
