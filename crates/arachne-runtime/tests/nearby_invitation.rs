use arachne_runtime::{close, create_lan, create_nearby, execute};
use serde_json::{Value, json};
use std::time::{Duration, Instant};

// The scenarios share both LAN discovery and the eight-node runtime budget.
static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn call(handle: i64, request: Value) -> Result<Value, String> {
    serde_json::from_slice(&execute(handle, &serde_json::to_vec(&request).unwrap())?)
        .map_err(|error| error.to_string())
}

#[test]
fn discovers_one_device_endpoint_and_sends_an_authenticated_invitation_handoff() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let sender = create_nearby(&[111; 32]).unwrap();
    let receiver = create_nearby(&[112; 32]).unwrap();
    let workspace = create_lan(&[113; 32]).unwrap();
    let receiver_id =
        call(receiver, json!({"op":"endpoint_info"})).unwrap()["endpoint_key"].clone();
    let workspace_id =
        call(workspace, json!({"op":"endpoint_info"})).unwrap()["endpoint_key"].clone();
    let deadline = Instant::now() + Duration::from_secs(12);
    loop {
        let endpoints = call(sender, json!({"op":"nearby_endpoints"})).unwrap()["endpoints"]
            .as_array()
            .unwrap()
            .clone();
        if endpoints.contains(&receiver_id) {
            assert!(!endpoints.contains(&workspace_id));
            break;
        }
        assert!(
            Instant::now() < deadline,
            "receiver was not discovered locally"
        );
    }

    let invitation = b"arachne://join#focused-nearby-check".to_vec();
    let sending = std::thread::spawn({
        let receiver_id = receiver_id.clone();
        let invitation = invitation.clone();
        move || {
            call(
                sender,
                json!({"op":"send_nearby_invitation","peer":receiver_id,"invitation":invitation}),
            )
        }
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    let received = loop {
        let value = call(receiver, json!({"op":"poll_admission"})).unwrap();
        if value["state"] == "nearby_invitation_received" {
            break value;
        }
        assert!(
            Instant::now() < deadline,
            "nearby invitation was not received"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(received["state"], "nearby_invitation_received");
    assert_eq!(received["invitation"], json!(invitation));
    assert_eq!(
        sending.join().unwrap().unwrap()["state"],
        "nearby_invitation_sent"
    );
    close(sender).unwrap();
    close(receiver).unwrap();
    close(workspace).unwrap();
}

#[test]
fn advertises_only_an_explicit_bounded_workspace_invitation() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let admin = create_nearby(&[121; 32]).unwrap();
    let joiner = create_nearby(&[122; 32]).unwrap();
    let invitation = b"arachne://join#focused-nearby-workspace".to_vec();
    let admin_id = call(admin, json!({"op":"endpoint_info"})).unwrap()["endpoint_key"].clone();
    let deadline = Instant::now() + Duration::from_secs(12);
    loop {
        let endpoints = call(joiner, json!({"op":"nearby_endpoints"})).unwrap()["endpoints"]
            .as_array()
            .unwrap()
            .clone();
        if endpoints.contains(&admin_id) {
            break;
        }
        assert!(Instant::now() < deadline, "advertiser was not discovered");
    }

    fn discover(joiner: i64, admin: i64) -> Value {
        let query = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(12);
            loop {
                let value = call(joiner, json!({"op":"nearby_workspaces"})).unwrap();
                if value["endpoints_checked"].as_u64().unwrap() > 0 {
                    return value;
                }
                assert!(Instant::now() < deadline, "advertiser was not discovered");
            }
        });
        let deadline = Instant::now() + Duration::from_secs(12);
        loop {
            let value = call(admin, json!({"op":"poll_admission"})).unwrap();
            if value["state"] == "nearby_workspace_replied" {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "workspace query was not received"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        query.join().unwrap()
    }

    assert_eq!(discover(joiner, admin)["workspaces"], json!([]));
    call(
        admin,
        json!({
            "op":"set_nearby_workspace",
            "mode":"open_joining",
            "invitation":invitation,
            "workspace":vec![8; 32],
        }),
    )
    .unwrap();
    let found = discover(joiner, admin);
    assert_eq!(found["workspaces"][0]["peer"], admin_id);
    assert_eq!(found["workspaces"][0]["mode"], "open_joining");
    assert_eq!(found["workspaces"][0]["invitation"], json!(invitation));

    let second_invitation = b"arachne://join#focused-nearby-workspace-2".to_vec();
    call(
        admin,
        json!({
            "op":"set_nearby_workspace",
            "mode":"request_access",
            "workspace_name":"Second workspace",
            "invitation":second_invitation,
            "workspace":vec![9; 32],
        }),
    )
    .unwrap();
    let found = discover(joiner, admin);
    assert_eq!(found["workspaces"].as_array().unwrap().len(), 2);
    assert!(found["workspaces"].as_array().unwrap().iter().any(|row| {
        row["invitation"] == json!(invitation) && row["mode"] == "open_joining"
    }));
    assert!(found["workspaces"].as_array().unwrap().iter().any(|row| {
        row["invitation"] == json!(b"arachne://join#focused-nearby-workspace-2".to_vec())
            && row["mode"] == "request_access"
    }));

    call(
        admin,
        json!({
            "op":"set_nearby_workspace",
            "mode":"request_access",
            "invitation":invitation,
            "workspace":vec![8; 32],
        }),
    )
    .unwrap();
    assert_eq!(
        discover(joiner, admin)["workspaces"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["invitation"] == json!(invitation))
            .unwrap()["mode"],
        "request_access"
    );
    assert!(
        call(
            admin,
            json!({
                "op":"set_nearby_workspace",
                "mode":"unknown",
                "invitation":invitation,
            })
        )
        .is_err()
    );

    call(admin, json!({"op":"set_nearby_workspace","mode":null,"workspace":vec![8; 32]})).unwrap();
    let remaining = discover(joiner, admin);
    assert_eq!(remaining["workspaces"].as_array().unwrap().len(), 1);
    assert_eq!(remaining["workspaces"][0]["workspace_name"], "Second workspace");
    call(admin, json!({"op":"set_nearby_workspace","mode":null})).unwrap();
    assert_eq!(discover(joiner, admin)["workspaces"], json!([]));
    close(admin).unwrap();
    close(joiner).unwrap();
}

#[test]
fn nearby_results_identify_three_workspaces_and_reject_unsafe_names() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let admins: Vec<_> = (131..=133)
        .map(|id| create_nearby(&[id; 32]).unwrap())
        .collect();
    let joiner = create_nearby(&[134; 32]).unwrap();
    let names = ["Field Coordination", "Supply", "Field Coordination"];
    for (index, admin) in admins.iter().enumerate() {
        call(*admin, json!({"op":"set_nearby_workspace","mode":"request_access",
            "workspace_name":names[index],"invitation":format!("arachne://join#workspace-{index}").into_bytes()})).unwrap();
    }
    for bad in [
        "".to_owned(),
        "x".repeat(81),
        "Team\nSupply".to_owned(),
        "Team\u{202e}".to_owned(),
    ] {
        assert!(
            call(
                admins[0],
                json!({"op":"set_nearby_workspace","mode":"open_joining",
            "workspace_name":bad,"invitation":[1]})
            )
            .is_err()
        );
    }
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if call(joiner, json!({"op":"nearby_endpoints"})).unwrap()["endpoints"]
            .as_array()
            .unwrap()
            .len()
            == 3
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "three advertisers were not discovered"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let found = loop {
        let query = std::thread::spawn(move || {
            call(joiner, json!({"op":"nearby_workspaces"})).unwrap()
        });
        while !query.is_finished() {
            for admin in &admins {
                call(*admin, json!({"op":"poll_admission"})).unwrap();
            }
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(10));
        }
        let found = query.join().unwrap();
        if found["workspaces"].as_array().unwrap().len() == 3 {
            break found;
        }
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(20));
    };
    for (index, name) in names.iter().enumerate() {
        let row = &found["workspaces"][index];
        assert_eq!(row["workspace_name"], *name);
        assert_eq!(row["mode"], "request_access");
        assert!(row.get("members").is_none() && row.get("administrator").is_none());
    }
    for admin in admins {
        close(admin).unwrap();
    }
    close(joiner).unwrap();
}
