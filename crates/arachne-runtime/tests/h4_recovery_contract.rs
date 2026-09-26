use arachne_runtime::{
    Client, ClientConfig, CurrentViewRequest, CurrentViewStatus, DirectRecoveryRequest,
    DirectRecoveryStatus, ErrorCode, Key32, MemberId, Network, ResourceRequest, ResourceStatus,
};

#[test]
fn native_recovery_operations_are_available_without_json() {
    let client = Client::open(ClientConfig {
        network: Network::Direct,
        secret: None,
        transport: Default::default(),
        storage: None,
    })
    .unwrap();
    assert_eq!(
        client.next_direct_gap().unwrap_err().code(),
        ErrorCode::WrongState
    );
    let direct = DirectRecoveryRequest {
        author: MemberId::from_bytes([1; 32]),
        revision: 1,
        topic: "objects/test".into(),
        recipients: vec![],
        after: 0,
        through: 1,
    };
    assert_eq!(
        client.fetch_direct_recovery(direct).unwrap_err().code(),
        ErrorCode::WrongState
    );
    let current = CurrentViewRequest {
        peer: None,
        authority: MemberId::from_bytes([1; 32]),
        revision: 1,
        topic: "objects/test".into(),
        selector: Key32::from_bytes([2; 32]),
    };
    assert_eq!(
        client.fetch_current_view(current).unwrap_err().code(),
        ErrorCode::InvalidInput
    );
    assert!(matches!(
        client.resource(ResourceRequest::Cancel { id: 4 }).unwrap(),
        ResourceStatus::Cancelled
    ));
    client.close().unwrap();
    assert_eq!(
        client.poll_current_view().unwrap_err().code(),
        ErrorCode::Closed
    );
    assert_eq!(
        client.poll_direct_recovery().unwrap_err().code(),
        ErrorCode::Closed
    );
}

#[cfg(feature = "uniffi")]
#[test]
fn core_exports_recovery_metadata_directly() {
    fn exported<T: uniffi::TypeId<arachne_runtime::UniFfiTag>>() {}
    exported::<CurrentViewStatus>();
    exported::<DirectRecoveryStatus>();
    exported::<ResourceStatus>();
}
