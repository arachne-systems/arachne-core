use arachne_api::{ApiError, EndpointId, MemberId, RecordId, WorkspaceId};
use arachne_runtime::{
    Client, EndpointInfo, MemberInfo, ReceivedProtectedPublication, RecoveryStage,
    WorkspaceCandidate, WorkspaceInfo,
};

// These assignments are a compile-time contract. SDK bindings must not convert IDs or counts.
fn workspace_shape(value: WorkspaceInfo) {
    let _: WorkspaceId = value.workspace;
    let _: u64 = value.member_count;
}
fn endpoint_shape(value: EndpointInfo) {
    let _: EndpointId = value.endpoint_key;
}
fn member_shape(value: MemberInfo) {
    let _: MemberId = value.id;
    let _: EndpointId = value.endpoint;
}
fn object_shape(value: ReceivedProtectedPublication) {
    let _: WorkspaceId = value.workspace;
    let _: MemberId = value.member;
    let _: EndpointId = value.endpoint;
    let _: RecordId = value.id;
}
fn candidate_shape(value: &WorkspaceCandidate) {
    let _: WorkspaceId = value.workspace();
}

#[test]
fn typed_shapes_are_shared_by_rust_and_foreign_callers() {
    let _: fn(&Client, u64, &[String]) -> Result<(), ApiError> = Client::install_member_policy;
    let _ = (
        workspace_shape,
        endpoint_shape,
        member_shape,
        object_shape,
        candidate_shape,
    );
    // A foreign host must keep a default arm as this public enum grows.
    let _ = RecoveryStage::AlreadyCovered;
}
