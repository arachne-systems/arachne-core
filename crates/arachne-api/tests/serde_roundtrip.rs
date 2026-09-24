use arachne_api::{
    API_VERSION, ApiError, Capabilities, EndpointId, ErrorCode, Event, Feature, Network,
    PublicationId, TopicName, WorkspaceId,
};
use serde_json::json;

fn round_trip<T>(value: &T) -> T
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    serde_json::from_value(serde_json::to_value(value).unwrap()).unwrap()
}

#[test]
fn ids_serialize_as_hex_strings() {
    let id = WorkspaceId::from_bytes([0xa5; 32]);
    assert_eq!(serde_json::to_value(id).unwrap(), json!("a5".repeat(32)));
    assert_eq!(round_trip(&id), id);
    let publication = PublicationId::from_bytes([3; 16]);
    assert_eq!(round_trip(&publication), publication);
}

#[test]
fn ids_reject_bad_input_on_deserialize() {
    assert!(serde_json::from_value::<WorkspaceId>(json!("00")).is_err());
    assert!(serde_json::from_value::<WorkspaceId>(json!([0, 1])).is_err());
    assert!(serde_json::from_value::<PublicationId>(json!("00".repeat(32))).is_err());
}

#[test]
fn topic_name_serializes_as_string_and_validates() {
    let topic = TopicName::new("cot/sa").unwrap();
    assert_eq!(serde_json::to_value(&topic).unwrap(), json!("cot/sa"));
    assert_eq!(round_trip(&topic), topic);
    assert!(serde_json::from_value::<TopicName>(json!("a//b")).is_err());
}

#[test]
fn error_code_serializes_as_its_number() {
    for code in ErrorCode::ALL {
        let value = serde_json::to_value(code).unwrap();
        assert_eq!(value, json!(code.as_u32()));
        assert_eq!(round_trip(code), *code);
    }
    assert!(serde_json::from_value::<ErrorCode>(json!(4)).is_err());
    assert!(serde_json::from_value::<ErrorCode>(json!("closed")).is_err());
}

#[test]
fn api_error_round_trips() {
    let errors = [
        ApiError::Closed,
        ApiError::InvalidInput {
            field: "topic".into(),
            reason: "empty".into(),
        },
        ApiError::Transport {
            code: ErrorCode::Timeout,
            peer: Some(EndpointId::from_bytes([2; 32])),
            detail: "no route".into(),
        },
        ApiError::Internal {
            detail: "boom".into(),
        },
    ];
    for error in errors {
        let back = round_trip(&error);
        assert_eq!(back, error);
        assert_eq!(back.code(), error.code());
    }
}

#[test]
fn network_includes_tor_in_every_build() {
    assert!(Network::ALL.contains(&Network::Tor));
    assert_eq!(serde_json::to_value(Network::Tor).unwrap(), json!("tor"));
    assert_eq!(
        serde_json::to_value(Network::RelayOnly).unwrap(),
        json!("relay_only")
    );
    for network in Network::ALL {
        assert_eq!(round_trip(network), *network);
    }
}

#[test]
fn event_round_trips() {
    for event in [Event::AdmissionRequest, Event::Presence, Event::Closed] {
        assert_eq!(round_trip(&event), event);
    }
}

#[test]
fn capabilities_carry_the_api_version() {
    assert_eq!(API_VERSION, 2, "bump deliberately with the change log");
    let caps = Capabilities::new(
        vec![Network::Direct, Network::Lan],
        vec![Feature::ResourceTransfer],
    );
    assert_eq!(caps.api_version, API_VERSION);
    assert_eq!(round_trip(&caps), caps);
}
