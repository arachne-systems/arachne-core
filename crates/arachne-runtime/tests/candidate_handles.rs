//! A5/ADR step 5: candidates are opaque, bound to their kind and their
//! client, and can be used one time only.
use arachne_runtime::{
    Client, ClientConfig, ErrorCode, MemoryProvider, Network, StorageConfig, execute,
};
use serde_json::{Value, json};

fn open(secret: u8, provider: &MemoryProvider) -> std::sync::Arc<Client> {
    Client::open(ClientConfig {
        network: Network::Direct,
        secret: Some(([secret; 32]).into()),
        transport: Default::default(),
        storage: Some((StorageConfig::memory(provider)).into()),
    })
    .unwrap()
}

#[test]
fn a_candidate_adopts_once_and_only_on_its_client() {
    let provider = MemoryProvider::default();
    let owner = open(61, &provider);
    let other = open(62, &provider);
    owner.create_workspace("Owner", None).unwrap();
    other.create_workspace("Other", None).unwrap();
    let renamed = owner.stage_workspace_name("Renamed").unwrap();
    // Another client refuses it before it touches either session.
    let error = other.adopt_admission(&renamed).unwrap_err();
    assert_eq!(error.code(), ErrorCode::WrongState, "{error:?}");
    let info = owner.adopt_admission(&renamed).unwrap();
    assert_eq!(info.workspace_name.as_deref(), Some("Renamed"));
    // Used: a second adoption is stale and changes nothing.
    let error = owner.adopt_admission(&renamed).unwrap_err();
    assert_eq!(error.code(), ErrorCode::CandidateStale, "{error:?}");
    assert!(!renamed.discard().unwrap());
    // Both sessions still work.
    let next = owner.stage_workspace_name("Again").unwrap();
    owner.adopt_admission(&next).unwrap();
    let theirs = other.stage_workspace_name("Theirs").unwrap();
    other.adopt_admission(&theirs).unwrap();
    owner.close().unwrap();
    other.close().unwrap();
}

#[test]
fn discard_and_drop_release_the_session() {
    let provider = MemoryProvider::default();
    let owner = open(63, &provider);
    let created = owner.create_workspace("Owner", None).unwrap();
    let first = owner.stage_workspace_name("First").unwrap();
    assert_eq!(first.workspace(), created.workspace);
    assert!(first.discard().unwrap());
    let error = owner.adopt_admission(&first).unwrap_err();
    assert_eq!(error.code(), ErrorCode::CandidateStale, "{error:?}");
    // Dropped without adoption: core discards it.
    drop(owner.stage_workspace_name("Dropped").unwrap());
    let last = owner.stage_workspace_name("Last").unwrap();
    assert_eq!(
        owner
            .adopt_admission(&last)
            .unwrap()
            .workspace_name
            .as_deref(),
        Some("Last")
    );
    owner.close().unwrap();
}

#[test]
fn a_candidate_of_one_kind_never_adopts_as_another_over_json() {
    let provider = MemoryProvider::default();
    let handle = arachne_runtime::create(Some(&[64; 32])).unwrap();
    arachne_runtime::attach_storage(handle, StorageConfig::memory(&provider)).unwrap();
    let call = |request: Value| -> Result<Value, String> {
        serde_json::from_slice(&execute(handle, &serde_json::to_vec(&request).unwrap())?)
            .map_err(|error| error.to_string())
    };
    let created = call(json!({"op":"create_workspace","display_name":"Owner"})).unwrap();
    let staged = call(json!({"op":"stage_workspace_name","workspace_name":"Named"})).unwrap();
    for op in [
        "adopt_join",
        "adopt_publication",
        "adopt_reception",
        "adopt_recovery",
    ] {
        let error = call(json!({"op":op,"candidate":staged["candidate"]})).unwrap_err();
        assert!(error.contains("kind"), "{op}: {error}");
    }
    // Nothing moved: the right op still adopts it.
    let adopted = call(json!({"op":"adopt_admission","candidate":staged["candidate"]})).unwrap();
    assert_eq!(adopted["epoch"], created["epoch"]);
    assert_eq!(adopted["workspace_name"], "Named");
    // discard_candidate is bound to its token.
    let staged = call(json!({"op":"stage_workspace_name","workspace_name":"Other"})).unwrap();
    let mut wrong: Vec<u8> = serde_json::from_value(staged["candidate"].clone()).unwrap();
    wrong[36] ^= 1;
    assert_eq!(
        call(json!({"op":"discard_candidate","candidate":wrong})).unwrap()["discarded"],
        false
    );
    assert_eq!(
        call(json!({"op":"discard_candidate","candidate":staged["candidate"]})).unwrap()["discarded"],
        true
    );
    arachne_runtime::close(handle).unwrap();
}

#[test]
fn a_join_candidate_never_adopts_as_an_admission() {
    use arachne_security::Workspace;
    let provider = MemoryProvider::default();
    let admin = Workspace::create(
        &arachne_security::EndpointKey::generate().unwrap(),
        "Administrator",
    )
    .unwrap();
    let (registered, invite, checkpoint) = admin.prepare_invitation(0, false, false).unwrap();
    let admin = registered.workspace;
    let handle = arachne_runtime::create(Some(&[65; 32])).unwrap();
    arachne_runtime::attach_storage(handle, StorageConfig::memory(&provider)).unwrap();
    let call = |request: Value| -> Result<Value, String> {
        serde_json::from_slice(&execute(handle, &serde_json::to_vec(&request).unwrap())?)
            .map_err(|error| error.to_string())
    };
    let bytes = |value: &Value| -> Vec<u8> { serde_json::from_value(value.clone()).unwrap() };
    let pending = call(
        json!({"op":"begin_join","invitation":invite.export_secret_token().as_slice(),
        "checkpoint":checkpoint,"display_name":"Joiner"}),
    )
    .unwrap();
    let endpoint = serde_json::from_value(pending["endpoint"].clone()).unwrap();
    let prepared = admin
        .prepare_admission(endpoint, &bytes(&pending["admission_request"]))
        .unwrap();
    let auth = prepared.authorization;
    let staged = call(json!({"op":"stage_join","welcome":prepared.welcome,"commits":[{"commit":prepared.commit,
        "authorization":{"invitation_key":auth.invitation_key,"grant_signature":auth.grant_signature.as_slice(),
            "redemption_signature":auth.redemption_signature.as_slice()}}]}))
    .unwrap();
    let error = call(json!({"op":"adopt_admission","candidate":staged["candidate"]})).unwrap_err();
    assert!(error.contains("kind"), "{error}");
    let joined = call(json!({"op":"adopt_join","candidate":staged["candidate"]})).unwrap();
    assert_eq!(joined["members"], 2);
    arachne_runtime::close(handle).unwrap();
}
