use arachne_api::{Capabilities, Event, Limits, Network};

#[test]
fn events_have_a_complete_unique_foreign_inventory() {
    assert_eq!(Event::ALL.len(), 11);
    let names: std::collections::BTreeSet<_> = Event::ALL
        .iter()
        .map(|event| serde_json::to_string(event).unwrap())
        .collect();
    assert_eq!(names.len(), Event::ALL.len());
    assert!(Event::ALL.contains(&Event::CurrentViewReady));
    assert!(Event::ALL.contains(&Event::Closed));
}

#[test]
fn capabilities_carry_the_owners_limits() {
    let limits = Limits::default()
        .with_max_sessions(3)
        .with_max_overlay_paths(7);
    let capabilities = Capabilities::new(vec![Network::Direct], vec![], limits);
    assert_eq!(capabilities.limits, limits);
}
