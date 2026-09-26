use arachne_api::{
    AttemptId, EndpointId, ErrorCode, MemberId, PublicationId, RecordId, TopicName, WorkspaceId,
};

#[test]
fn byte_ids_have_the_documented_lengths() {
    assert_eq!(EndpointId::LEN, 32);
    assert_eq!(MemberId::LEN, 32);
    assert_eq!(WorkspaceId::LEN, 32);
    assert_eq!(AttemptId::LEN, 32);
    assert_eq!(RecordId::LEN, 16);
    assert_eq!(PublicationId::LEN, 16);
}

#[test]
fn from_slice_rejects_the_wrong_length_with_invalid_id() {
    for len in [0, 1, 31, 33, 64] {
        let error = WorkspaceId::from_slice(&vec![1; len]).unwrap_err();
        assert_eq!(error.code(), ErrorCode::InvalidId, "len {len}");
    }
    for len in [0, 15, 17, 32] {
        let error = RecordId::from_slice(&vec![1; len]).unwrap_err();
        assert_eq!(error.code(), ErrorCode::InvalidId, "len {len}");
    }
    assert_eq!(
        WorkspaceId::from_slice(&[9; 32]).unwrap().as_bytes(),
        &[9; 32]
    );
    assert_eq!(RecordId::from_slice(&[9; 16]).unwrap().to_bytes(), [9; 16]);
}

#[test]
fn hex_round_trips_and_is_lowercase() {
    let mut bytes = [0u8; 32];
    bytes[0] = 0xab;
    bytes[31] = 0x0f;
    let id = EndpointId::from_bytes(bytes);
    let text = id.to_string();
    assert_eq!(text.len(), 64);
    assert!(text.starts_with("ab"));
    assert!(text.ends_with("0f"));
    assert_eq!(EndpointId::from_hex(&text).unwrap(), id);
    assert_eq!(EndpointId::from_hex(&text.to_uppercase()).unwrap(), id);
    assert_eq!(text.parse::<EndpointId>().unwrap(), id);
    assert_eq!(format!("{id:?}"), format!("EndpointId({text})"));
}

#[test]
fn from_hex_rejects_bad_text() {
    let good = "00".repeat(32);
    let bad = [
        String::new(),
        "0".repeat(63),
        "0".repeat(65),
        format!("{}zz", "00".repeat(31)),
        format!("{}é", "0".repeat(62)),
        format!(" {}", &good[1..]),
    ];
    for text in bad {
        let error = MemberId::from_hex(&text).unwrap_err();
        assert_eq!(error.code(), ErrorCode::InvalidId, "{text:?}");
    }
}

#[test]
fn different_id_kinds_are_different_types() {
    // Compile-time property; this documents it. `WorkspaceId == MemberId`
    // does not compile.
    let workspace = WorkspaceId::from_bytes([1; 32]);
    let member = MemberId::from_bytes([1; 32]);
    assert_eq!(workspace.as_bytes(), member.as_bytes());
}

#[test]
fn topic_names_follow_the_routing_rules() {
    for good in ["a", "chat", "cot/sa", "a.b-c_d/E9", &"x".repeat(128)] {
        assert_eq!(TopicName::new(good).unwrap().as_str(), good);
    }
    for bad in [
        "",
        "/",
        "a/",
        "/a",
        "a//b",
        "a b",
        "a*",
        "a+b",
        "é",
        &"x".repeat(129),
    ] {
        let error = TopicName::new(bad).unwrap_err();
        assert_eq!(error.code(), ErrorCode::InvalidInput, "{bad:?}");
    }
}
