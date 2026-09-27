//! `arachne_routing::Topic` and `arachne_api::TopicName` must accept and
//! reject exactly the same names (ADR A1/A4, open point for step 2). The
//! routing crate stays free of dependencies, so this crate, which depends on
//! both, pins the two rule sets together. Only accept/reject is compared:
//! the two check in a different order and give different error text.

fn same_decision(name: &str) {
    let routing = arachne_routing::Topic::new(name).is_ok();
    let api = arachne_api::TopicName::new(name).is_ok();
    assert_eq!(routing, api, "rules differ for {name:?}");
}

#[test]
fn routing_topic_and_api_topic_name_accept_the_same_names() {
    let long = "a".repeat(128);
    let too_long = "a".repeat(129);
    let long_segments = format!("{}/{}", "a".repeat(63), "b".repeat(64));
    let cases = [
        "",
        "a",
        "cot/sa",
        "chat/room/1",
        "a.b-c_d",
        long.as_str(),
        too_long.as_str(),
        long_segments.as_str(),
        "/",
        "/a",
        "a/",
        "a//b",
        "//",
        "a b",
        "a\tb",
        "a\nb",
        "é",
        "a/é",
        "ä/b",
        "A/Z/0/9",
        "*",
        "a/*",
        "#",
        "a+b",
        "a:b",
        "a\\b",
        "..",
        "./.",
        "-",
        "_",
        "\0",
    ];
    for name in cases {
        same_decision(name);
    }
    // Every single ASCII byte, alone and inside a name.
    for byte in 0u8..=127 {
        let text = (byte as char).to_string();
        same_decision(&text);
        same_decision(&format!("a{text}b"));
        same_decision(&format!("a/{text}"));
    }
    // Lengths around the bound, with and without separators.
    for length in 120..=136 {
        same_decision(&"x".repeat(length));
        same_decision(&format!("{}/y", "x".repeat(length.saturating_sub(2))));
    }
}
