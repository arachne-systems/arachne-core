use arachne_runtime::{
    AdmissionResponse, Client, ClientConfig, JoinProgress, MemberUpdate, MemoryProvider, Network,
    StorageConfig, WorkspacePhase, WorkspaceProgress,
};
use std::sync::Arc;

#[test]
fn native_driver_results_have_no_open_json() {
    let provider = MemoryProvider::default();
    let client = Client::open(ClientConfig {
        network: Network::Direct,
        secret: Some([37; 32].into()),
        transport: Default::default(),
        storage: Some(Arc::new(StorageConfig::memory(&provider))),
    })
    .unwrap();
    client.create_workspace("Owner", None).unwrap();
    let progress: WorkspaceProgress = client.drive_workspace().unwrap();
    assert_eq!(progress.activity.phase, WorkspacePhase::Active);
    let _: Option<Arc<MemberUpdate>> = client.poll_membership_update().unwrap();
    let _: fn(&Client) -> Result<JoinProgress, arachne_runtime::ApiError> = Client::drive_join;
    let _: fn(
        &Client,
        arachne_runtime::EndpointId,
    ) -> Result<AdmissionResponse, arachne_runtime::ApiError> = Client::request_admission;
    client.close().unwrap();
}
