use arachne_node::Node;
use arachne_runtime::{close, create, describe, execute, wait_for_work};
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

fn call(handle: i64, request: Value) -> Result<Value, String> {
    serde_json::from_slice(&execute(handle, &serde_json::to_vec(&request).unwrap())?)
        .map_err(|error| error.to_string())
}

fn bytes(value: &Value) -> Vec<u8> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|byte| byte.as_u64().unwrap() as u8)
        .collect()
}

#[test]
fn a_parked_host_wakes_on_control_arrival_and_on_close() {
    let owner = create(Some(&[41; 32])).unwrap();
    call(
        owner,
        json!({"op":"create_workspace","display_name":"Signal owner","workspace_name":"Signal"}),
    )
    .unwrap();
    let info: Value = serde_json::from_str(&describe(owner).unwrap()).unwrap();
    let peer: [u8; 32] = bytes(&info["endpoint_key"]).try_into().unwrap();
    let port: u16 = info["bound_address"]
        .as_str()
        .unwrap()
        .rsplit_once(':')
        .unwrap()
        .1
        .parse()
        .unwrap();
    let address = SocketAddr::from(([127, 0, 0, 1], port));

    let (woke, observed) = mpsc::channel();
    let waiter = thread::spawn(move || {
        woke.send(wait_for_work(owner).unwrap()).unwrap();
        woke.send(wait_for_work(owner).unwrap()).unwrap();
    });

    // Parked: nothing has arrived yet.
    assert!(observed.recv_timeout(Duration::from_millis(300)).is_err());

    let sender = thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let (node, _) = Node::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
            node.add_address_hint(peer, address).await.unwrap();
            node.request_control(peer, b"DFND\x01").await.unwrap()
        })
    });

    assert_eq!(observed.recv_timeout(Duration::from_secs(5)), Ok(true));
    let handled = call(owner, json!({"op":"poll_admission"})).unwrap();
    assert_eq!(handled["state"], "nearby_identity_replied");
    sender.join().unwrap();

    // Second wait is parked again; close must release it with `false`.
    assert!(observed.recv_timeout(Duration::from_millis(300)).is_err());
    close(owner).unwrap();
    assert_eq!(observed.recv_timeout(Duration::from_secs(5)), Ok(false));
    waiter.join().unwrap();
    assert!(wait_for_work(owner).is_err());
}
