//! Fork choice for competing membership commits at one epoch (ADR A2, section 1).
//!
//! Every node computes the same key from the step alone, with no local state:
//! `ForkKey = (class, SHA-256(commit bytes))`. The lower key wins. The class
//! decides first, so a removal always beats a step that keeps or adds access,
//! whatever the hash. The hash only breaks ties inside one class.
use super::{ManagementAction, MembershipAuthorization};

/// Priority class of a membership step. A lower class wins a fork.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum ForkClass {
    /// Remove, Leave: takes keys away from a member.
    Removal = 0,
    /// Demote, DisableInvitation: reduces rights, no member loses keys.
    Revocation = 1,
    /// Promote and invitation create / approve / decline.
    Management = 2,
    /// Admission, AdmissionBatch: adds keys.
    Admission = 3,
    /// Member self-update. No authorization variant produces it yet (ADR step 5).
    SelfUpdate = 4,
}

impl ForkClass {
    /// Class of one management action.
    pub fn of_action(action: &ManagementAction) -> Self {
        // Exhaustive on purpose: a new action must pick its class.
        match action {
            ManagementAction::Remove(_) | ManagementAction::Leave(..) => Self::Removal,
            ManagementAction::Demote(_) | ManagementAction::DisableInvitation(_) => {
                Self::Revocation
            }
            ManagementAction::Promote(_)
            | ManagementAction::CreateInvitation(..)
            | ManagementAction::CreateAutomaticInvitation(..)
            | ManagementAction::CreateRequestInvitation(..)
            | ManagementAction::DeclineInvitationRequest(..)
            | ManagementAction::ApproveInvitation(..) => Self::Management,
        }
    }

    /// Class of one verified membership authorization.
    pub fn of(authorization: &MembershipAuthorization) -> Self {
        // Exhaustive on purpose: ADR step 5 adds SelfUpdate here.
        match authorization {
            MembershipAuthorization::Management(action) => Self::of_action(action),
            MembershipAuthorization::Admission(_) | MembershipAuthorization::AdmissionBatch(_) => {
                Self::Admission
            }
        }
    }

    /// Wire value of the class.
    pub fn to_u8(self) -> u8 {
        self as u8
    }

    /// Parse a wire value. Unknown values are rejected.
    pub fn from_u8(value: u8) -> Result<Self, &'static str> {
        Ok(match value {
            0 => Self::Removal,
            1 => Self::Revocation,
            2 => Self::Management,
            3 => Self::Admission,
            4 => Self::SelfUpdate,
            _ => return Err("unknown fork class"),
        })
    }
}

/// Total order key for one membership step. Field order is load-bearing:
/// the derived `Ord` compares the class first, then the digest bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ForkKey {
    class: ForkClass,
    digest: [u8; 32],
}

/// Encoded size of a `ForkKey`: one class byte and the 32-byte digest.
pub const FORK_KEY_BYTES: usize = 33;

impl ForkKey {
    /// Key for commit bytes in a given class. The digest is plain SHA-256 of
    /// the exact commit bytes, with no domain tag (ADR A2 section 1).
    pub fn new(class: ForkClass, commit: &[u8]) -> Self {
        use sha2::{Digest, Sha256};
        Self {
            class,
            digest: Sha256::digest(commit).into(),
        }
    }
    pub fn class(&self) -> ForkClass {
        self.class
    }
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
    /// True when this key wins against `other`. Equal keys do not beat each other.
    pub fn beats(&self, other: &Self) -> bool {
        self < other
    }
    pub fn to_bytes(&self) -> [u8; FORK_KEY_BYTES] {
        let mut bytes = [0; FORK_KEY_BYTES];
        bytes[0] = self.class.to_u8();
        bytes[1..].copy_from_slice(&self.digest);
        bytes
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() != FORK_KEY_BYTES {
            return Err("invalid fork key length");
        }
        Ok(Self {
            class: ForkClass::from_u8(bytes[0])?,
            digest: bytes[1..].try_into().unwrap(),
        })
    }
}

/// Fork key of one step.
///
/// Precondition: `authorization` has already been verified against exactly
/// this `commit` (for example by `MembershipVerifier`). The class comes from the
/// authorization, so an unverified tag could relabel a Promote as a Removal.
/// `commit` must be the exact commit bytes stored in the membership history.
pub fn fork_key(authorization: &MembershipAuthorization, commit: &[u8]) -> ForkKey {
    ForkKey::new(ForkClass::of(authorization), commit)
}

/// The winning key of two competing steps at one fork point. The lower key
/// wins. The result does not depend on argument order.
pub fn winner(a: ForkKey, b: ForkKey) -> ForkKey {
    a.min(b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AdmissionAuthorization;

    /// SplitMix64: a small deterministic generator for seeded property tests.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        }
        fn bytes(&mut self) -> Vec<u8> {
            let length = (self.next() % 96) as usize;
            (0..length).map(|_| self.next() as u8).collect()
        }
        fn class(&mut self) -> ForkClass {
            ForkClass::from_u8((self.next() % 5) as u8).unwrap()
        }
        fn key(&mut self) -> ForkKey {
            let class = self.class();
            ForkKey::new(class, &self.bytes())
        }
    }

    fn admission() -> AdmissionAuthorization {
        AdmissionAuthorization {
            invitation_key: [7; 32],
            grant_signature: [8; 64],
            redemption_signature: [9; 64],
        }
    }

    const CLASSES: [ForkClass; 5] = [
        ForkClass::Removal,
        ForkClass::Revocation,
        ForkClass::Management,
        ForkClass::Admission,
        ForkClass::SelfUpdate,
    ];

    #[test]
    fn class_order_is_removal_revocation_management_admission_self_update() {
        for pair in CLASSES.windows(2) {
            assert!(
                pair[0] < pair[1],
                "{:?} must win against {:?}",
                pair[0],
                pair[1]
            );
        }
        for (value, class) in CLASSES.iter().enumerate() {
            assert_eq!(class.to_u8(), value as u8);
            assert_eq!(ForkClass::from_u8(value as u8).unwrap(), *class);
        }
        assert!(ForkClass::from_u8(5).is_err());
        assert!(ForkClass::from_u8(255).is_err());
    }

    #[test]
    fn every_action_and_authorization_has_the_adr_class() {
        let id = [1; 32];
        let cases = [
            (ManagementAction::Remove(id), ForkClass::Removal),
            (ManagementAction::Leave(id, [2; 64]), ForkClass::Removal),
            (ManagementAction::Demote(id), ForkClass::Revocation),
            (
                ManagementAction::DisableInvitation(id),
                ForkClass::Revocation,
            ),
            (ManagementAction::Promote(id), ForkClass::Management),
            (
                ManagementAction::CreateInvitation(id, 5, true),
                ForkClass::Management,
            ),
            (
                ManagementAction::CreateAutomaticInvitation(id, 5),
                ForkClass::Management,
            ),
            (
                ManagementAction::CreateRequestInvitation(id, 5),
                ForkClass::Management,
            ),
            (
                ManagementAction::DeclineInvitationRequest(id, [3; 32]),
                ForkClass::Management,
            ),
            (
                ManagementAction::ApproveInvitation(id, [3; 32]),
                ForkClass::Management,
            ),
        ];
        for (action, class) in cases {
            assert_eq!(ForkClass::of_action(&action), class, "{action:?}");
            assert_eq!(
                ForkClass::of(&MembershipAuthorization::Management(action)),
                class,
                "{action:?}"
            );
        }
        assert_eq!(
            ForkClass::of(&MembershipAuthorization::Admission(admission())),
            ForkClass::Admission
        );
        assert_eq!(
            ForkClass::of(&MembershipAuthorization::AdmissionBatch(vec![
                admission();
                2
            ])),
            ForkClass::Admission
        );
    }

    #[test]
    fn digest_is_plain_sha256_of_the_commit_bytes() {
        // Known answer: SHA-256("abc"). A domain tag here would split nodes.
        let expected: [u8; 32] = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        let key = fork_key(&MembershipAuthorization::Admission(admission()), b"abc");
        assert_eq!(key.class(), ForkClass::Admission);
        assert_eq!(key.digest(), expected);
        assert_eq!(ForkKey::new(ForkClass::Removal, b"abc").digest(), expected);
    }

    #[test]
    fn codec_round_trips_and_rejects_bad_input() {
        let mut rng = Rng(11);
        for _ in 0..200 {
            let key = rng.key();
            let bytes = key.to_bytes();
            assert_eq!(bytes[0], key.class().to_u8());
            assert_eq!(&bytes[1..], &key.digest());
            assert_eq!(ForkKey::from_bytes(&bytes).unwrap(), key);
        }
        let good = ForkKey::new(ForkClass::Removal, b"x").to_bytes();
        assert!(ForkKey::from_bytes(&good[..32]).is_err());
        let mut long = good.to_vec();
        long.push(0);
        assert!(ForkKey::from_bytes(&long).is_err());
        let mut bad_class = good;
        bad_class[0] = 5;
        assert!(ForkKey::from_bytes(&bad_class).is_err());
    }

    #[test]
    fn order_is_total_antisymmetric_and_matches_class_then_digest() {
        let mut rng = Rng(0x00a2_f0c4);
        let keys: Vec<ForkKey> = (0..400).map(|_| rng.key()).collect();
        for a in &keys {
            for b in keys.iter().take(60) {
                // Exactly one of a<b, a==b, b<a holds.
                let relations = [a < b, a == b, b < a].iter().filter(|x| **x).count();
                assert_eq!(relations, 1);
                // Antisymmetry of "beats".
                assert!(!(a.beats(b) && b.beats(a)));
                assert_eq!(a.beats(b), a < b);
                // Same order as the explicit (class, digest) tuple.
                assert_eq!(
                    a.cmp(b),
                    (a.class().to_u8(), a.digest()).cmp(&(b.class().to_u8(), b.digest()))
                );
                // Winner is commutative and is one of the inputs.
                let w = winner(*a, *b);
                assert_eq!(w, winner(*b, *a));
                assert!(w == *a || w == *b);
                assert!(w <= *a && w <= *b);
            }
        }
        // Transitivity through associativity of winner.
        for triple in keys.chunks(3).filter(|chunk| chunk.len() == 3) {
            let (a, b, c) = (triple[0], triple[1], triple[2]);
            assert_eq!(winner(a, winner(b, c)), winner(winner(a, b), c));
            if a < b && b < c {
                assert!(a < c);
            }
        }
    }

    #[test]
    fn key_is_deterministic_for_the_same_step() {
        let mut rng = Rng(42);
        for _ in 0..200 {
            let commit = rng.bytes();
            let action = ManagementAction::Remove([rng.next() as u8; 32]);
            let authorization = MembershipAuthorization::Management(action);
            assert_eq!(
                fork_key(&authorization, &commit),
                fork_key(&authorization, &commit)
            );
            assert_eq!(
                fork_key(&authorization, &commit),
                ForkKey::new(ForkClass::Removal, &commit)
            );
        }
    }

    #[test]
    fn removals_beat_adds_regardless_of_hash() {
        let mut rng = Rng(7);
        let remove = MembershipAuthorization::Management(ManagementAction::Remove([4; 32]));
        let leave = MembershipAuthorization::Management(ManagementAction::Leave([4; 32], [5; 64]));
        let add = MembershipAuthorization::AdmissionBatch(vec![admission()]);
        let promote = MembershipAuthorization::Management(ManagementAction::Promote([6; 32]));
        let mut lower_hash_losers = 0;
        for _ in 0..2_000 {
            let removal = fork_key(
                if rng.next().is_multiple_of(2) {
                    &remove
                } else {
                    &leave
                },
                &rng.bytes(),
            );
            for other in [&add, &promote] {
                let key = fork_key(other, &rng.bytes());
                if key.digest() < removal.digest() {
                    lower_hash_losers += 1;
                }
                assert_eq!(winner(removal, key), removal);
                assert_eq!(winner(key, removal), removal);
                assert!(removal.beats(&key) && !key.beats(&removal));
            }
        }
        // Non-vacuous: many cases had the lower hash on the losing side.
        assert!(lower_hash_losers > 500, "{lower_hash_losers}");
    }

    #[test]
    fn inside_one_class_the_lower_digest_wins() {
        let mut rng = Rng(99);
        for _ in 0..500 {
            let class = rng.class();
            let (a, b) = (
                ForkKey::new(class, &rng.bytes()),
                ForkKey::new(class, &rng.bytes()),
            );
            let expected = if a.digest() <= b.digest() { a } else { b };
            assert_eq!(winner(a, b), expected);
        }
    }

    #[test]
    fn every_observer_order_picks_the_same_winner() {
        // T1, pure part: observers see the same competing steps in any order.
        let mut rng = Rng(0x7_1);
        for _ in 0..100 {
            let keys = [rng.key(), rng.key(), rng.key(), rng.key()];
            let expected = *keys.iter().min().unwrap();
            let mut orders = Vec::new();
            permutations(&mut keys.to_vec(), 0, &mut orders);
            assert_eq!(orders.len(), 24);
            for order in orders {
                let chosen = order.iter().copied().reduce(winner).unwrap();
                assert_eq!(chosen, expected);
            }
        }
    }

    fn permutations(items: &mut Vec<ForkKey>, start: usize, out: &mut Vec<Vec<ForkKey>>) {
        if start == items.len() {
            out.push(items.clone());
            return;
        }
        for index in start..items.len() {
            items.swap(start, index);
            permutations(items, start + 1, out);
            items.swap(start, index);
        }
    }
}
