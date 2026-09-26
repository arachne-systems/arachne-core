//! Production must not accept the development fixture operations.
#[cfg(not(feature = "test-fixtures"))]
#[test]
fn production_rejects_fixture_ops_at_decode() {
    let handle = arachne_runtime::create(None).unwrap();
    for request in [
        serde_json::json!({"op":"install_verified_policy", "workspace":vec![0;32], "revision":1, "endpoints":[]}),
        serde_json::json!({"op":"publish", "workspace":vec![0;32], "revision":1, "topic":"test", "payload":[]}),
        serde_json::json!({"op":"poll"}),
    ] {
        let result = arachne_runtime::execute(handle, &serde_json::to_vec(&request).unwrap());
        assert!(
            result
                .as_ref()
                .is_err_and(|e| e.contains("unknown variant")),
            "{request}: {result:?}"
        );
    }
    arachne_runtime::close(handle).unwrap();
}

#[cfg(not(feature = "debug-rig"))]
#[test]
fn production_rejects_debug_control_exchange() {
    let request = serde_json::json!({"op":"control_exchange", "peer":vec![0;32], "payload":[]});
    let result = arachne_runtime::execute(0, &serde_json::to_vec(&request).unwrap());
    assert!(
        result
            .as_ref()
            .is_err_and(|e| e.contains("unknown variant")),
        "{result:?}"
    );
}
