#![no_main]

use arachne_security::{
    BranchState, ForkKey, Invitation, OrderStep, RevocationOrder, decode_membership_step,
    encode_membership_step,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 2 * 1024 * 1024 {
        return;
    }

    if let Ok(invitation) = Invitation::from_bytes(data) {
        let encoded = invitation.export_secret_token();
        assert!(Invitation::from_bytes(&encoded).is_ok());
    }
    if let Ok((authorization, commit)) = decode_membership_step(data) {
        let encoded = encode_membership_step(&authorization, &commit).unwrap();
        let (roundtrip_authorization, roundtrip_commit) = decode_membership_step(&encoded).unwrap();
        assert_eq!(
            encode_membership_step(&roundtrip_authorization, &roundtrip_commit).unwrap(),
            encoded
        );
    }
    if let Ok(key) = ForkKey::from_bytes(data) {
        assert_eq!(key.to_bytes().as_slice(), data);
    }
    if let Ok(order) = RevocationOrder::from_bytes(data) {
        assert_eq!(order.to_bytes().as_slice(), data);
    }
    if let Ok(step) = OrderStep::from_bytes(data) {
        let encoded = step.to_bytes().unwrap();
        assert_eq!(
            OrderStep::from_bytes(&encoded).unwrap().to_bytes().unwrap(),
            encoded
        );
    }
    if let Ok(state) = BranchState::decode(data) {
        let encoded = state.encode();
        assert_eq!(BranchState::decode(&encoded).unwrap().encode(), encoded);
    }
});
