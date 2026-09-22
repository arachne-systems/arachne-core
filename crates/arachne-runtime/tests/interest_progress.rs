use arachne_runtime::{close, create, describe, execute};
use serde_json::{Value, json};
use std::{
    net::UdpSocket,
    time::{Duration, Instant},
};

fn call(handle: i64, request: Value) -> Value {
    serde_json::from_slice(&execute(handle, &serde_json::to_vec(&request).unwrap()).unwrap())
        .unwrap()
}

fn drain_interests(handle: i64) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !call(handle, json!({"op":"poll_interest"})).is_null() {
        assert!(Instant::now() < deadline, "interest repair did not settle");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn live_policy(publisher: &Value, subscriber: &Value) -> Value {
    json!([
        {"peer":publisher["endpoint_key"], "publish":["streams/live"], "subscribe":[]},
        {"peer":subscriber["endpoint_key"], "publish":[], "subscribe":["streams/live"]}
    ])
}

#[test]
fn failed_interest_retries_when_publisher_becomes_ready() {
    let publisher = create(None).unwrap();
    let subscriber = create(None).unwrap();
    let info = |handle| serde_json::from_str::<Value>(&describe(handle).unwrap()).unwrap();
    let a = info(publisher);
    let b = info(subscriber);
    let workspace = json!(vec![82; 32]);
    for (handle, peer) in [(publisher, &b), (subscriber, &a)] {
        call(
            handle,
            json!({"op":"add_address_hint", "peer":peer["endpoint_key"],
            "address":peer["bound_address"].as_str().unwrap().replace("0.0.0.0:", "127.0.0.1:")}),
        );
    }
    // The publisher's transport is up while its workspace is still restoring.
    call(
        subscriber,
        json!({"op":"install_verified_policy", "workspace":workspace,
        "revision":1, "endpoints":live_policy(&a, &b)}),
    );
    call(
        subscriber,
        json!({"op":"set_interest", "workspace":workspace,
        "revision":1, "topic":"streams/live", "subscribed":true}),
    );
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        let result = call(subscriber, json!({"op":"poll_interest"}));
        if result["state"] == "interest_observed" {
            assert_eq!(result["admission"]["failed"].as_array().unwrap().len(), 1);
            break;
        }
        assert!(
            Instant::now() < deadline,
            "initial failure was not observed"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    call(
        publisher,
        json!({"op":"install_verified_policy", "workspace":workspace,
        "revision":1, "endpoints":live_policy(&a, &b)}),
    );
    // No new address hint, local network callback or presence announcement.
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        let result = call(subscriber, json!({"op":"poll_interest"}));
        if result["state"] == "interest_observed" && result["admission"]["failed"] == json!([]) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "failed subscription was never retried"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        call(
            publisher,
            json!({"op":"publish", "workspace":workspace,
        "revision":1, "topic":"streams/live", "payload":[7]})
        )["admitted"],
        json!([b["endpoint_key"]])
    );
    assert_eq!(
        call(subscriber, json!({"op":"poll"}))["payload"],
        json!([7])
    );
    close(subscriber).unwrap();
    close(publisher).unwrap();
}

#[test]
fn desired_interest_repairs_after_publisher_restart() {
    let publisher_secret = [31; 32];
    let subscriber_secret = [32; 32];
    let mut publisher = create(Some(&publisher_secret)).unwrap();
    let subscriber = create(Some(&subscriber_secret)).unwrap();
    let info = |handle| serde_json::from_str::<Value>(&describe(handle).unwrap()).unwrap();
    let mut a = info(publisher);
    let b = info(subscriber);
    let workspace = json!(vec![79; 32]);
    for (handle, peer) in [(publisher, &b), (subscriber, &a)] {
        call(
            handle,
            json!({"op":"add_address_hint", "peer":peer["endpoint_key"],
            "address":peer["bound_address"].as_str().unwrap().replace("0.0.0.0:", "127.0.0.1:")}),
        );
        call(
            handle,
            json!({"op":"install_verified_policy", "workspace":workspace,
            "revision":1, "endpoints":live_policy(&a, &b)}),
        );
    }
    call(
        subscriber,
        json!({"op":"set_interest", "workspace":workspace,
        "revision":1, "topic":"streams/live", "subscribed":true}),
    );
    drain_interests(subscriber);
    assert_eq!(
        call(
            publisher,
            json!({"op":"publish", "workspace":workspace,
        "revision":1, "topic":"streams/live", "payload":[1]})
        )["admitted"],
        json!([b["endpoint_key"]])
    );
    assert_eq!(
        call(subscriber, json!({"op":"poll"}))["payload"],
        json!([1])
    );

    close(publisher).unwrap();
    publisher = create(Some(&publisher_secret)).unwrap();
    a = info(publisher);
    call(
        publisher,
        json!({"op":"add_address_hint", "peer":b["endpoint_key"],
        "address":b["bound_address"].as_str().unwrap().replace("0.0.0.0:", "127.0.0.1:")}),
    );
    call(
        publisher,
        json!({"op":"install_verified_policy", "workspace":workspace,
        "revision":1, "endpoints":live_policy(&a, &b)}),
    );
    assert_eq!(
        call(
            publisher,
            json!({"op":"publish", "workspace":workspace,
        "revision":1, "topic":"streams/live", "payload":[2]})
        )["admitted"],
        json!([])
    );

    call(
        subscriber,
        json!({"op":"add_address_hint", "peer":a["endpoint_key"],
        "address":a["bound_address"].as_str().unwrap().replace("0.0.0.0:", "127.0.0.1:")}),
    );
    drain_interests(subscriber);
    assert_eq!(
        call(
            publisher,
            json!({"op":"publish", "workspace":workspace,
        "revision":1, "topic":"streams/live", "payload":[3]})
        )["admitted"],
        json!([b["endpoint_key"]])
    );
    assert_eq!(
        call(subscriber, json!({"op":"poll"}))["payload"],
        json!([3])
    );
    close(subscriber).unwrap();
    close(publisher).unwrap();
}

#[test]
fn desired_interest_set_is_bounded_and_withdrawal_frees_capacity() {
    let subscriber = create(None).unwrap();
    let info: Value = serde_json::from_str(&describe(subscriber).unwrap()).unwrap();
    let workspace = json!(vec![80; 32]);
    let overflow_workspace = json!(vec![81; 32]);
    let topics: Vec<_> = (0..65).map(|n| format!("streams/desired_{n}")).collect();
    call(
        subscriber,
        json!({"op":"install_verified_policy", "workspace":workspace, "revision":1,
        "endpoints":[{"peer":info["endpoint_key"], "publish":[], "subscribe":&topics[..64]}]}),
    );
    call(
        subscriber,
        json!({"op":"install_verified_policy", "workspace":overflow_workspace, "revision":1,
        "endpoints":[{"peer":info["endpoint_key"], "publish":[], "subscribe":[topics[64]]}]}),
    );
    for topic in topics.iter().take(64) {
        call(
            subscriber,
            json!({"op":"set_interest", "workspace":workspace,
            "revision":1, "topic":topic, "subscribed":true}),
        );
        drain_interests(subscriber);
    }
    let overflow = execute(
        subscriber,
        &serde_json::to_vec(&json!({"op":"set_interest", "workspace":overflow_workspace,
        "revision":1, "topic":topics[64], "subscribed":true}))
        .unwrap(),
    );
    assert!(
        overflow
            .unwrap_err()
            .contains("desired interest set is full")
    );
    call(
        subscriber,
        json!({"op":"set_interest", "workspace":workspace,
        "revision":1, "topic":topics[0], "subscribed":false}),
    );
    drain_interests(subscriber);
    call(
        subscriber,
        json!({"op":"set_interest", "workspace":overflow_workspace,
        "revision":1, "topic":topics[64], "subscribed":true}),
    );
    drain_interests(subscriber);
    close(subscriber).unwrap();
}

#[test]
fn offline_interest_does_not_block_live_receive() {
    let publisher = create(None).unwrap();
    let subscriber = create(None).unwrap();
    let absent = create(None).unwrap();
    let info = |handle| serde_json::from_str::<Value>(&describe(handle).unwrap()).unwrap();
    let a = info(publisher);
    let b = info(subscriber);
    let c = info(absent);
    close(absent).unwrap();
    // Keep the UDP port open without answering QUIC; no routing/setup error can
    // substitute for the actual five-second connection wait.
    let blackhole = UdpSocket::bind("127.0.0.1:0").unwrap();
    let workspace = json!(vec![77; 32]);
    for (handle, peer) in [(publisher, &b), (subscriber, &a)] {
        call(
            handle,
            json!({"op":"add_address_hint", "peer":peer["endpoint_key"],
            "address":peer["bound_address"].as_str().unwrap().replace("0.0.0.0:", "127.0.0.1:")}),
        );
        call(
            handle,
            json!({"op":"add_address_hint", "peer":c["endpoint_key"],
            "address":blackhole.local_addr().unwrap().to_string()}),
        );
        call(
            handle,
            json!({"op":"install_verified_policy", "workspace":workspace, "revision":1,
            "endpoints":[
                {"peer":a["endpoint_key"], "publish":["streams/live"], "subscribe":[]},
                {"peer":b["endpoint_key"], "publish":[], "subscribe":["streams/live"]},
                {"peer":c["endpoint_key"], "publish":["streams/live"], "subscribe":[]}
            ]}),
        );
    }
    // Run with FABRIC_TEST_BLOCKING_INTEREST=1 before production edits to retain
    // the old Android operation's behavioral RED. Default uses its replacement.
    let legacy = std::env::var_os("FABRIC_TEST_BLOCKING_INTEREST").is_some();
    let scope = workspace.clone();
    let started = Instant::now();
    let announcing = std::thread::spawn(move || {
        let mut request = json!({"op":if legacy {"subscribe"} else {"set_interest"},
            "workspace":scope, "revision":1, "topic":"streams/live"});
        if !legacy {
            request["subscribed"] = json!(true);
        }
        call(subscriber, request)
    });
    // Seeing actual publication admission proves the healthy peer received the
    // subscription and the receiver installed its own interest before timing.
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let sent = call(
            publisher,
            json!({"op":"publish", "workspace":workspace,
            "revision":1, "topic":"streams/live", "payload":[0,255,42]}),
        );
        if sent["admitted"] == json!([b["endpoint_key"]]) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "healthy subscription not observed"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    let receiving = Instant::now();
    let received = call(subscriber, json!({"op":"poll"}));
    let receive_wait = receiving.elapsed();
    assert_eq!(received["payload"], json!([0, 255, 42]));
    let announcement = announcing.join().unwrap();
    if !legacy {
        assert_eq!(announcement["state"], "interest_queued");
        assert_eq!(
            call(subscriber, json!({"op":"poll_interest"}))["state"],
            "interest_pending"
        );
        assert!(
            execute(
                subscriber,
                &serde_json::to_vec(&json!({"op":"unsubscribe", "workspace":workspace,
            "revision":1, "topic":"streams/live"}))
                .unwrap()
            )
            .unwrap_err()
            .contains("use set_interest")
        );
        let changing = Instant::now();
        for subscribed in [false, true, false, true, false] {
            let result = call(
                subscriber,
                json!({"op":"set_interest", "workspace":workspace,
                "revision":1, "topic":"streams/live", "subscribed":subscribed}),
            );
            assert_eq!(result["queued"], 1, "same-topic changes must coalesce");
        }
        assert!(
            changing.elapsed() < Duration::from_secs(1),
            "local interest waited on network"
        );
        // The publisher still has the old interest: rejection must come from
        // the receiving node's immediate local withdrawal.
        let denied = call(
            publisher,
            json!({"op":"publish", "workspace":workspace,
            "revision":1, "topic":"streams/live", "payload":[99]}),
        );
        assert_eq!(denied["admitted"], json!([]));
        assert_eq!(denied["failed"][0]["peer"], b["endpoint_key"]);
        assert!(call(subscriber, json!({"op":"poll"})).is_null());
        let deadline = Instant::now() + Duration::from_secs(12);
        let mut observed = Vec::new();
        loop {
            let value = call(subscriber, json!({"op":"poll_interest"}));
            if value.is_null() {
                break;
            }
            if value["state"] == "interest_observed" {
                observed.push(value);
            }
            assert!(
                Instant::now() < deadline,
                "coalesced announcement did not finish"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(observed.len(), 2);
        assert_eq!(observed[0]["subscribed"], true);
        assert_eq!(observed[1]["subscribed"], false);
        assert!(
            observed
                .iter()
                .all(|v| v["admission"]["failed"][0]["peer"] == c["endpoint_key"])
        );
        let withdrawn = call(
            publisher,
            json!({"op":"publish", "workspace":workspace,
            "revision":1, "topic":"streams/live", "payload":[100]}),
        );
        assert_eq!(withdrawn["admitted"], json!([]));
        assert_eq!(
            withdrawn["failed"],
            json!([]),
            "remote interest was resurrected"
        );
        // Queue an old-revision update, then replace its authority while the
        // prior announcement is in flight. Neither may restore the old policy.
        for subscribed in [true, false] {
            call(
                subscriber,
                json!({"op":"set_interest", "workspace":workspace,
                "revision":1, "topic":"streams/live", "subscribed":subscribed}),
            );
        }
        for handle in [publisher, subscriber] {
            call(
                handle,
                json!({"op":"install_verified_policy", "workspace":workspace, "revision":2,
                "endpoints":[
                    {"peer":a["endpoint_key"], "publish":["streams/live"], "subscribe":[]},
                    {"peer":b["endpoint_key"], "publish":[], "subscribe":[]}
                ]}),
            );
        }
        let deadline = Instant::now() + Duration::from_secs(7);
        while !call(subscriber, json!({"op":"poll_interest"})).is_null() {
            assert!(
                Instant::now() < deadline,
                "old revision work did not settle"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            call(
                publisher,
                json!({"op":"publish", "workspace":workspace,
            "revision":2, "topic":"streams/live", "payload":[101]})
            )["admitted"],
            json!([])
        );
        assert!(call(subscriber, json!({"op":"poll"})).is_null());
        // Keep a real offline announcement pending while filling the queue.
        // Overflow must reject before mutating local interest; a newer choice
        // for an already queued topic must still be accepted at capacity.
        let bounded_topics: Vec<_> = (0..63).map(|n| format!("streams/bound_{n}")).collect();
        let mut allowed = bounded_topics.clone();
        allowed.push("streams/live".into());
        call(
            subscriber,
            json!({"op":"install_verified_policy", "workspace":workspace, "revision":3,
            "endpoints":[
                {"peer":b["endpoint_key"], "publish":allowed, "subscribe":allowed},
                {"peer":c["endpoint_key"], "publish":allowed, "subscribe":[]}
            ]}),
        );
        call(
            subscriber,
            json!({"op":"install_verified_policy", "workspace":vec![78;32], "revision":1,
            "endpoints":[
                {"peer":b["endpoint_key"], "publish":["streams/overflow"], "subscribe":["streams/overflow"]}
            ]}),
        );
        call(
            subscriber,
            json!({"op":"set_interest", "workspace":workspace,
            "revision":3, "topic":"streams/live", "subscribed":true}),
        );
        for (index, topic) in allowed.iter().enumerate() {
            let report = call(
                subscriber,
                json!({"op":"set_interest", "workspace":workspace,
                "revision":3, "topic":topic, "subscribed":true}),
            );
            assert_eq!(report["queued"], index + 1);
        }
        let overflow = execute(
            subscriber,
            &serde_json::to_vec(&json!({"op":"set_interest",
            "workspace":vec![78;32], "revision":1, "topic":"streams/overflow", "subscribed":true}))
            .unwrap(),
        );
        assert!(
            overflow
                .unwrap_err()
                .contains("interest update queue is full")
        );
        assert_eq!(
            call(
                subscriber,
                json!({"op":"publish", "workspace":vec![78;32],
            "revision":1, "topic":"streams/overflow", "payload":[77]})
            )["admitted"],
            json!([]),
            "rejected update changed local interest"
        );
        for subscribed in [false, true] {
            assert_eq!(
                call(
                    subscriber,
                    json!({"op":"set_interest", "workspace":workspace,
                "revision":3, "topic":bounded_topics[0], "subscribed":subscribed})
                )["queued"],
                64
            );
            let report = call(
                subscriber,
                json!({"op":"publish", "workspace":workspace,
                "revision":3, "topic":bounded_topics[0], "payload":[78]}),
            );
            assert_eq!(
                report["admitted"],
                if subscribed {
                    json!([b["endpoint_key"]])
                } else {
                    json!([])
                }
            );
        }
        assert_eq!(
            call(subscriber, json!({"op":"poll"}))["payload"],
            json!([78])
        );
        // The announcement to the offline peer is either still dialing or has
        // already failed fast (the transport backs off unreachable peers). It
        // must never report that offline peer as reached.
        let progress = call(subscriber, json!({"op":"poll_interest"}));
        match progress["state"].as_str() {
            Some("interest_pending") => {}
            Some("interest_observed") => assert!(
                !progress["admission"]["failed"].as_array().unwrap().is_empty(),
                "an offline announcement reported no failed peer: {progress}"
            ),
            other => panic!("unexpected interest progress {other:?}: {progress}"),
        }
    }
    let elapsed = started.elapsed();
    let closing = Instant::now();
    close(subscriber).unwrap();
    assert!(
        closing.elapsed() < Duration::from_secs(4),
        "close waited for announcement"
    );
    close(publisher).unwrap();
    eprintln!(
        "INTEREST_PROGRESS legacy={legacy} receive_wait_ms={} elapsed_ms={}",
        receive_wait.as_millis(),
        elapsed.as_millis()
    );
    assert!(
        receive_wait < Duration::from_secs(1),
        "offline announcement blocked live receive: {receive_wait:?}"
    );
}
