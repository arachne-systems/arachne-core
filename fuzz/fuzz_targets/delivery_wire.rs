#![no_main]

use arachne_delivery::{
    RangeQuery,
    current::{CurrentViewQuery, LiveCurrentPacket},
    wire::{AvailableRangeQuery, CutoffQuery, DirectHead, DirectRangeQuery},
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 128 * 1024 {
        return;
    }

    if let Ok(value) = DirectHead::from_wire(data) {
        let encoded = value.to_wire().unwrap();
        assert_eq!(
            DirectHead::from_wire(&encoded).unwrap().to_wire().unwrap(),
            encoded
        );
    }
    if let Ok(value) = DirectRangeQuery::from_wire(data) {
        let encoded = value.to_wire().unwrap();
        assert_eq!(
            DirectRangeQuery::from_wire(&encoded)
                .unwrap()
                .to_wire()
                .unwrap(),
            encoded
        );
    }
    if let Ok(value) = AvailableRangeQuery::from_wire(data) {
        let encoded = value.to_wire().unwrap();
        assert_eq!(
            AvailableRangeQuery::from_wire(&encoded)
                .unwrap()
                .to_wire()
                .unwrap(),
            encoded
        );
    }
    if let Ok(value) = CutoffQuery::from_wire(data) {
        let encoded = value.to_wire().unwrap();
        assert_eq!(
            CutoffQuery::from_wire(&encoded).unwrap().to_wire().unwrap(),
            encoded
        );
    }
    if let Ok(value) = RangeQuery::from_wire(data) {
        let encoded = value.to_wire().unwrap();
        assert_eq!(
            RangeQuery::from_wire(&encoded).unwrap().to_wire().unwrap(),
            encoded
        );
    }
    if let Ok(value) = CurrentViewQuery::from_wire(data) {
        let encoded = value.to_wire().unwrap();
        assert_eq!(
            CurrentViewQuery::from_wire(&encoded)
                .unwrap()
                .to_wire()
                .unwrap(),
            encoded
        );
    }
    if let Ok(value) = LiveCurrentPacket::from_wire(data) {
        let encoded = value.to_wire().unwrap();
        assert_eq!(
            LiveCurrentPacket::from_wire(&encoded)
                .unwrap()
                .to_wire()
                .unwrap(),
            encoded
        );
    }
});
