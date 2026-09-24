//! Shared test helpers: endpoint keys by label (ADR A2 step 6). Tests name
//! endpoints by small labels; the endpoint is the key's public key.
#![allow(dead_code)]
use arachne_security::{EndpointKey, EndpointSigner};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

fn keys() -> &'static Mutex<HashMap<u64, &'static EndpointKey>> {
    static KEYS: OnceLock<Mutex<HashMap<u64, &'static EndpointKey>>> = OnceLock::new();
    KEYS.get_or_init(Default::default)
}

pub fn test_key(label: u64) -> &'static EndpointKey {
    keys()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .entry(label)
        .or_insert_with(|| Box::leak(Box::new(EndpointKey::generate().unwrap())))
}

pub fn test_endpoint(label: u64) -> [u8; 32] {
    test_key(label).endpoint()
}

/// The test key whose public key is `endpoint`.
pub fn test_key_for(endpoint: [u8; 32]) -> &'static EndpointKey {
    let key = keys()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .values()
        .copied()
        .find(|key| key.endpoint() == endpoint);
    key.expect("endpoint has no test key")
}
