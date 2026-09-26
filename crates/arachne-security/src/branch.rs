//! Retained pre-commit snapshots for unsettled epochs (ADR A2, sections 4 and 5).
//!
//! Terms used here:
//! - The **snapshot at epoch E** is the sealed workspace at epoch E, taken
//!   before the node adopts the commit whose parent epoch is E.
//! - The **fork epoch F** is the parent epoch of two competing commits. A node
//!   that loses at F loads the snapshot at F and replays the winning steps.
//! - Epoch E is **settled** when the commit out of E can no longer be replaced
//!   by this node. Snapshots at settled epochs are deleted.
//!
//! This is a pure data structure. Snapshots are opaque sealed bytes made by
//! the caller. It does not open them, verify steps, or talk to peers.
use super::{ForkKey, MAX_SEALED_BUNDLE};
use std::collections::VecDeque;

/// Epochs a node can go back. A fork deeper than this makes the node orphaned.
pub const ROLLBACK_EPOCHS: u64 = 64;
/// Upper bound for all retained snapshot bytes together.
pub const MAX_ROLLBACK_BYTES: usize = 16 * 1024 * 1024;
/// Upper bound for one sealed snapshot: a sealed workspace bundle.
pub const MAX_BRANCH_SNAPSHOT: usize = MAX_SEALED_BUNDLE;

const MAGIC: &[u8; 4] = b"DFBR";
const VERSION: u8 = 1;
/// Header of the split record form (`meta_record`).
const META_MAGIC: &[u8; 5] = b"DFBM\x01";
// magic, version, first_unsettled, orphaned, count
const HEADER: usize = 4 + 1 + 8 + 1 + 2;
// epoch, length
const ENTRY: usize = 8 + 4;
/// Upper bound for an encoded `BranchState` record.
pub const MAX_BRANCH_RECORD: usize = HEADER + ROLLBACK_EPOCHS as usize * ENTRY + MAX_ROLLBACK_BYTES;

/// Snapshots for unsettled epochs, the settlement mark, and the orphan flag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BranchState {
    first_unsettled: u64,
    snapshots: VecDeque<(u64, Vec<u8>)>,
    bytes: usize,
    orphaned: bool,
}

/// What a node does after it compares its step with a competing step.
#[derive(Debug)]
pub enum BranchDecision {
    /// The local step wins, or both steps are the same. The peer must switch.
    Keep,
    /// The remote step wins and the snapshot at the fork epoch exists.
    Switch(PreparedBranchSwitch),
    /// The remote step wins and no snapshot exists. The node must stop
    /// sending and ask an administrator for re-admission.
    Orphaned(BranchState),
}

/// A staged branch switch. Nothing changes until the caller adopts `state`
/// after it has replayed and saved the winning branch.
#[derive(Debug)]
pub struct PreparedBranchSwitch {
    fork_epoch: u64,
    snapshot: Vec<u8>,
    state: BranchState,
}

impl PreparedBranchSwitch {
    /// Parent epoch of the competing commits.
    pub fn fork_epoch(&self) -> u64 {
        self.fork_epoch
    }
    /// Sealed workspace at the fork epoch, before the losing commit.
    pub fn snapshot(&self) -> &[u8] {
        &self.snapshot
    }
    /// State to adopt after the switch. It keeps the snapshots at and below
    /// the fork epoch, and drops the losing snapshots above it. The snapshot
    /// at the fork epoch stays, so replay retains from `fork_epoch + 1`.
    pub fn state(&self) -> &BranchState {
        &self.state
    }
    pub fn into_parts(self) -> (Vec<u8>, BranchState) {
        (self.snapshot, self.state)
    }
}

impl BranchState {
    /// Empty state. Epochs below `first_unsettled` are settled. A joiner
    /// passes its join epoch: it holds no snapshot below it.
    pub fn new(first_unsettled: u64) -> Self {
        Self {
            first_unsettled,
            snapshots: VecDeque::new(),
            bytes: 0,
            orphaned: false,
        }
    }
    /// Lowest epoch that is not settled. Epochs below it are settled.
    pub fn first_unsettled(&self) -> u64 {
        self.first_unsettled
    }
    pub fn is_orphaned(&self) -> bool {
        self.orphaned
    }
    /// Retained snapshot epochs, lowest first.
    pub fn retained_epochs(&self) -> Vec<u64> {
        self.snapshots.iter().map(|(epoch, _)| *epoch).collect()
    }
    /// Sum of retained snapshot lengths.
    pub fn retained_bytes(&self) -> usize {
        self.bytes
    }
    /// Snapshot at epoch `epoch`, if it is retained.
    pub fn snapshot(&self, epoch: u64) -> Option<&[u8]> {
        let index = self
            .snapshots
            .binary_search_by_key(&epoch, |(retained, _)| *retained)
            .ok()?;
        Some(&self.snapshots[index].1)
    }

    /// Keep the sealed snapshot at `epoch` before the node adopts the commit
    /// out of `epoch`. Epochs must increase. After this call, epochs at or
    /// below `epoch - ROLLBACK_EPOCHS` are settled, and the oldest snapshots
    /// are evicted while the total passes `MAX_ROLLBACK_BYTES`.
    pub fn retain(&mut self, epoch: u64, sealed: Vec<u8>) -> Result<(), &'static str> {
        if self.orphaned {
            return Err("workspace branch is orphaned");
        }
        if sealed.is_empty() || sealed.len() > MAX_BRANCH_SNAPSHOT {
            return Err("invalid branch snapshot size");
        }
        if epoch < self.first_unsettled
            || self
                .snapshots
                .back()
                .is_some_and(|(last, _)| epoch <= *last)
        {
            return Err("branch snapshot epoch must follow the retained epochs");
        }
        self.bytes += sealed.len();
        self.snapshots.push_back((epoch, sealed));
        if let Some(settled) = epoch.checked_sub(ROLLBACK_EPOCHS) {
            self.settle_through(settled);
        }
        // One snapshot never exceeds the bound, so the newest always stays.
        while self.bytes > MAX_ROLLBACK_BYTES {
            let oldest = self.snapshots.front().map(|(epoch, _)| *epoch).unwrap();
            self.settle_through(oldest);
        }
        Ok(())
    }

    /// Settle every epoch at or below `epoch` and delete its snapshot. The
    /// settlement mark never goes down.
    pub fn settle_through(&mut self, epoch: u64) {
        self.first_unsettled = self.first_unsettled.max(epoch.saturating_add(1));
        while let Some((oldest, _)) = self.snapshots.front() {
            if *oldest > epoch {
                break;
            }
            let (_, sealed) = self.snapshots.pop_front().unwrap();
            self.bytes -= sealed.len();
        }
    }

    /// Settlement by observation. `roster` is the member list of epoch
    /// `epoch`. `reports` are `(member, epoch)` pairs that the caller already
    /// checked are on this chain. Epoch E settles only when every member of E
    /// reported epoch E + 1 or later: a report at E does not prove that the
    /// member adopted the commit out of E. Returns true when E is settled.
    pub fn settle_reported(
        &mut self,
        epoch: u64,
        roster: &[[u8; 32]],
        reports: &[([u8; 32], u64)],
    ) -> bool {
        if epoch < self.first_unsettled {
            return true;
        }
        let Some(next) = epoch.checked_add(1) else {
            return false;
        };
        let all_reported = !roster.is_empty()
            && roster.iter().all(|member| {
                reports
                    .iter()
                    .any(|(reporter, reported)| reporter == member && *reported >= next)
            });
        if all_reported {
            self.settle_through(epoch);
        }
        all_reported
    }

    /// Stage a switch to a winning branch at `fork_epoch`. None when no
    /// snapshot exists there (settled, evicted, before join, or orphaned).
    pub fn prepare_branch_switch(&self, fork_epoch: u64) -> Option<PreparedBranchSwitch> {
        if self.orphaned {
            return None;
        }
        let snapshot = self.snapshot(fork_epoch)?.to_vec();
        let mut state = self.clone();
        while state
            .snapshots
            .back()
            .is_some_and(|(epoch, _)| *epoch > fork_epoch)
        {
            let (_, sealed) = state.snapshots.pop_back().unwrap();
            state.bytes -= sealed.len();
        }
        Some(PreparedBranchSwitch {
            fork_epoch,
            snapshot,
            state,
        })
    }

    /// The orphaned state: no snapshots, and no further retention.
    pub fn orphaned(&self) -> BranchState {
        BranchState {
            first_unsettled: self.first_unsettled,
            snapshots: VecDeque::new(),
            bytes: 0,
            orphaned: true,
        }
    }

    /// Apply the fork rule at `fork_epoch`. The fork key always decides the
    /// winner; the retained snapshots decide only how this node moves.
    /// Both keys must be computed by this node from verified steps.
    pub fn resolve(&self, fork_epoch: u64, local: ForkKey, remote: ForkKey) -> BranchDecision {
        if self.orphaned {
            return BranchDecision::Orphaned(self.clone());
        }
        if !remote.beats(&local) {
            return BranchDecision::Keep;
        }
        match self.prepare_branch_switch(fork_epoch) {
            Some(prepared) => BranchDecision::Switch(prepared),
            None => BranchDecision::Orphaned(self.orphaned()),
        }
    }

    /// Versioned binary record. No older version is accepted.
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(HEADER + self.snapshots.len() * ENTRY + self.bytes);
        bytes.extend(MAGIC);
        bytes.push(VERSION);
        bytes.extend(self.first_unsettled.to_be_bytes());
        bytes.push(u8::from(self.orphaned));
        bytes.extend((self.snapshots.len() as u16).to_be_bytes());
        for (epoch, sealed) in &self.snapshots {
            bytes.extend(epoch.to_be_bytes());
            bytes.extend((sealed.len() as u32).to_be_bytes());
            bytes.extend(sealed);
        }
        bytes
    }

    /// The record split for a store with a per-record bound (1 MiB): a small
    /// header (`DFBM`) and one record per snapshot. One snapshot is at most
    /// `MAX_BRANCH_SNAPSHOT`, so each part fits one record.
    pub fn meta_record(&self) -> Vec<u8> {
        let mut bytes = META_MAGIC.to_vec();
        bytes.extend(self.first_unsettled.to_be_bytes());
        bytes.push(u8::from(self.orphaned));
        bytes.extend((self.snapshots.len() as u16).to_be_bytes());
        for (epoch, _) in &self.snapshots {
            bytes.extend(epoch.to_be_bytes());
        }
        bytes
    }

    /// The retained snapshots, lowest epoch first.
    pub fn snapshots(&self) -> impl Iterator<Item = (u64, &[u8])> {
        self.snapshots
            .iter()
            .map(|(epoch, sealed)| (*epoch, sealed.as_slice()))
    }

    /// Rebuild from `meta_record` and the snapshot records. The snapshot set
    /// must be exactly the one the header names; every bound of `decode`
    /// applies.
    pub fn from_parts(meta: &[u8], snapshots: &[(u64, Vec<u8>)]) -> Result<Self, &'static str> {
        use super::storage::take;
        let mut rest = meta;
        if take(&mut rest, META_MAGIC.len())? != META_MAGIC {
            return Err("branch record format not supported");
        }
        let header = take(&mut rest, 8 + 1 + 2)?;
        let count = u16::from_be_bytes(header[9..11].try_into().unwrap()) as usize;
        if count > ROLLBACK_EPOCHS as usize
            || rest.len() != count * 8
            || snapshots.len() != count
        {
            return Err("branch snapshots do not match the branch record");
        }
        let mut bytes = MAGIC.to_vec();
        bytes.push(VERSION);
        bytes.extend(header);
        for (index, (epoch, sealed)) in snapshots.iter().enumerate() {
            if rest[index * 8..index * 8 + 8] != epoch.to_be_bytes() {
                return Err("branch snapshots do not match the branch record");
            }
            if sealed.len() > MAX_BRANCH_SNAPSHOT {
                return Err("invalid branch snapshot size");
            }
            bytes.extend(epoch.to_be_bytes());
            bytes.extend((sealed.len() as u32).to_be_bytes());
            bytes.extend(sealed);
        }
        Self::decode(&bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, &'static str> {
        use super::storage::take;
        if bytes.len() > MAX_BRANCH_RECORD {
            return Err("branch record is too large");
        }
        let mut rest = bytes;
        if take(&mut rest, MAGIC.len())? != MAGIC || take(&mut rest, 1)?[0] != VERSION {
            return Err("branch record format not supported");
        }
        let first_unsettled = u64::from_be_bytes(take(&mut rest, 8)?.try_into().unwrap());
        let orphaned = match take(&mut rest, 1)?[0] {
            0 => false,
            1 => true,
            _ => return Err("invalid branch orphan flag"),
        };
        let count = u16::from_be_bytes(take(&mut rest, 2)?.try_into().unwrap()) as usize;
        if count > ROLLBACK_EPOCHS as usize || (orphaned && count != 0) {
            return Err("invalid branch snapshot count");
        }
        let mut state = Self::new(first_unsettled);
        state.orphaned = orphaned;
        for _ in 0..count {
            let epoch = u64::from_be_bytes(take(&mut rest, 8)?.try_into().unwrap());
            let length = u32::from_be_bytes(take(&mut rest, 4)?.try_into().unwrap()) as usize;
            if length == 0 || length > MAX_BRANCH_SNAPSHOT {
                return Err("invalid branch snapshot size");
            }
            if epoch < first_unsettled
                || epoch - first_unsettled >= ROLLBACK_EPOCHS
                || state
                    .snapshots
                    .back()
                    .is_some_and(|(last, _)| epoch <= *last)
            {
                return Err("invalid branch snapshot epoch");
            }
            state.bytes += length;
            if state.bytes > MAX_ROLLBACK_BYTES {
                return Err("branch snapshots exceed the byte bound");
            }
            state
                .snapshots
                .push_back((epoch, take(&mut rest, length)?.to_vec()));
        }
        if !rest.is_empty() {
            return Err("trailing bytes after branch record");
        }
        Ok(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ForkClass, ForkKey};

    fn sealed(epoch: u64, length: usize) -> Vec<u8> {
        (0..length)
            .map(|index| (epoch as usize + index) as u8 | 1)
            .collect()
    }

    fn filled(range: std::ops::RangeInclusive<u64>) -> BranchState {
        let mut state = BranchState::new(*range.start());
        for epoch in range {
            state.retain(epoch, sealed(epoch, 40)).unwrap();
        }
        state
    }

    /// Two keys of one class where the first wins on the digest alone.
    fn ordered_pair(class: ForkClass) -> (ForkKey, ForkKey) {
        let a = ForkKey::new(class, b"commit-a");
        let b = ForkKey::new(class, b"commit-b");
        if a < b { (a, b) } else { (b, a) }
    }

    #[test]
    fn retains_and_finds_snapshots_by_epoch() {
        let state = filled(0..=5);
        assert_eq!(state.retained_epochs(), vec![0, 1, 2, 3, 4, 5]);
        assert_eq!(state.snapshot(3), Some(&sealed(3, 40)[..]));
        assert_eq!(state.snapshot(6), None);
        assert_eq!(state.retained_bytes(), 6 * 40);
        assert_eq!(state.first_unsettled(), 0);
        assert!(!state.is_orphaned());
    }

    #[test]
    fn retain_rejects_bad_input() {
        let mut state = filled(3..=5);
        let before = state.clone();
        assert!(state.retain(6, Vec::new()).is_err());
        assert!(state.retain(6, vec![1; MAX_BRANCH_SNAPSHOT + 1]).is_err());
        assert!(state.retain(5, sealed(5, 40)).is_err());
        assert!(state.retain(4, sealed(4, 40)).is_err());
        assert_eq!(state, before);
        let mut settled = BranchState::new(10);
        assert!(settled.retain(9, sealed(9, 40)).is_err());
        settled.retain(10, sealed(10, 40)).unwrap();
        // A snapshot of the exact maximum size is accepted.
        settled.retain(11, vec![1; MAX_BRANCH_SNAPSHOT]).unwrap();
    }

    #[test]
    fn count_bound_keeps_the_last_rollback_window() {
        let mut state = BranchState::new(0);
        for epoch in 0..=200 {
            state.retain(epoch, sealed(epoch, 40)).unwrap();
            assert!(state.retained_epochs().len() as u64 <= ROLLBACK_EPOCHS);
        }
        let epochs = state.retained_epochs();
        assert_eq!(epochs.len(), 64);
        assert_eq!(epochs[0], 137);
        assert_eq!(*epochs.last().unwrap(), 200);
        assert_eq!(state.first_unsettled(), 137);
        assert_eq!(state.retained_bytes(), 64 * 40);
    }

    #[test]
    fn window_is_by_epoch_distance_even_with_gaps() {
        let mut state = BranchState::new(0);
        state.retain(0, sealed(0, 40)).unwrap();
        state.retain(10, sealed(10, 40)).unwrap();
        state.retain(70, sealed(70, 40)).unwrap();
        // 70 - 64 = 6: epochs at or below 6 are settled by the window.
        assert_eq!(state.retained_epochs(), vec![10, 70]);
        assert_eq!(state.first_unsettled(), 7);
        state.retain(200, sealed(200, 40)).unwrap();
        assert_eq!(state.retained_epochs(), vec![200]);
        assert_eq!(state.first_unsettled(), 137);
    }

    #[test]
    fn fork_at_depth_64_switches_and_depth_65_is_orphaned() {
        // Snapshots 0..=99 retained; after the last commit the node is at 100.
        // Depth = current epoch - fork epoch.
        let state = filled(0..=99);
        let current = 100;
        let (win, lose) = ordered_pair(ForkClass::Management);
        match state.resolve(current - 64, lose, win) {
            BranchDecision::Switch(prepared) => {
                assert_eq!(prepared.fork_epoch(), 36);
                assert_eq!(prepared.snapshot(), &sealed(36, 40)[..]);
            }
            other => panic!("expected a switch, got {other:?}"),
        }
        match state.resolve(current - 65, lose, win) {
            BranchDecision::Orphaned(orphaned) => assert!(orphaned.is_orphaned()),
            other => panic!("expected orphaned, got {other:?}"),
        }
    }

    #[test]
    fn byte_bound_evicts_oldest_first_and_settles_them() {
        let size = MAX_BRANCH_SNAPSHOT;
        let fits = MAX_ROLLBACK_BYTES / size;
        assert!(
            fits < ROLLBACK_EPOCHS as usize,
            "bytes must bind before count"
        );
        let mut state = BranchState::new(0);
        for epoch in 0..30 {
            state.retain(epoch, vec![epoch as u8 | 1; size]).unwrap();
            assert!(state.retained_bytes() <= MAX_ROLLBACK_BYTES);
        }
        let epochs = state.retained_epochs();
        assert_eq!(epochs.len(), fits);
        assert_eq!(*epochs.last().unwrap(), 29);
        assert_eq!(epochs[0], 30 - fits as u64);
        assert_eq!(state.first_unsettled(), epochs[0]);
        assert_eq!(state.retained_bytes(), fits * size);
        assert_eq!(state.snapshot(29).unwrap()[0], 29 | 1);
    }

    #[test]
    fn settles_only_when_every_member_reported_the_next_epoch() {
        let (a, b, c) = ([1; 32], [2; 32], [3; 32]);
        let mut state = filled(0..=8);
        // A report at exactly E does not settle E.
        assert!(!state.settle_reported(4, &[a, b], &[(a, 4), (b, 4)]));
        // One member behind.
        assert!(!state.settle_reported(4, &[a, b], &[(a, 5), (b, 4)]));
        // One member missing; a report from a non-member does not count.
        assert!(!state.settle_reported(4, &[a, b], &[(a, 9), (c, 9)]));
        // Empty roster never settles.
        assert!(!state.settle_reported(4, &[], &[(a, 9)]));
        assert_eq!(state.first_unsettled(), 0);
        assert_eq!(state.retained_epochs().len(), 9);
        // Every member at E + 1 or later: E and all below it settle.
        assert!(state.settle_reported(4, &[a, b], &[(a, 5), (b, 4), (b, 7)]));
        assert_eq!(state.first_unsettled(), 5);
        assert_eq!(state.retained_epochs(), vec![5, 6, 7, 8]);
        // Already settled stays settled.
        assert!(state.settle_reported(2, &[a], &[]));
    }

    #[test]
    fn settlement_mark_never_goes_down() {
        let mut state = filled(0..=8);
        state.settle_through(5);
        assert_eq!(state.first_unsettled(), 6);
        state.settle_through(3);
        assert_eq!(state.first_unsettled(), 6);
        assert_eq!(state.retained_epochs(), vec![6, 7, 8]);
        // Settling past the last snapshot empties the store.
        state.settle_through(20);
        assert_eq!(state.first_unsettled(), 21);
        assert!(state.retained_epochs().is_empty());
        assert_eq!(state.retained_bytes(), 0);
        state.retain(21, sealed(21, 40)).unwrap();
    }

    #[test]
    fn fork_key_decides_and_settlement_decides_only_how() {
        // T8, security part.
        let mut state = filled(0..=5);
        let (low, high) = ordered_pair(ForkClass::Admission);
        // Local wins or both are the same step: keep.
        assert!(matches!(state.resolve(3, low, high), BranchDecision::Keep));
        assert!(matches!(state.resolve(3, low, low), BranchDecision::Keep));
        // Remote wins with a snapshot at the fork epoch: switch.
        match state.resolve(3, high, low) {
            BranchDecision::Switch(prepared) => {
                assert_eq!(prepared.fork_epoch(), 3);
                assert_eq!(prepared.state().retained_epochs(), vec![0, 1, 2, 3]);
                let (snapshot, _) = prepared.into_parts();
                assert_eq!(snapshot, sealed(3, 40));
            }
            other => panic!("expected a switch, got {other:?}"),
        }
        // A removal beats an admission whatever the digests are.
        let removal = ForkKey::new(ForkClass::Removal, b"remove");
        assert!(matches!(
            state.resolve(3, low, removal),
            BranchDecision::Switch(_)
        ));
        // Settle through 3; a competing commit at 3 arrives.
        state.settle_through(3);
        assert!(matches!(state.resolve(3, low, high), BranchDecision::Keep));
        match state.resolve(3, high, low) {
            BranchDecision::Orphaned(orphaned) => {
                assert!(orphaned.is_orphaned());
                assert!(orphaned.retained_epochs().is_empty());
                assert_eq!(orphaned.retained_bytes(), 0);
            }
            other => panic!("expected orphaned, got {other:?}"),
        }
        // The input state is not changed by resolve.
        assert!(!state.is_orphaned());
        assert_eq!(state.retained_epochs(), vec![4, 5]);
    }

    #[test]
    fn a_joiner_below_its_join_epoch_is_orphaned_when_it_loses() {
        let state = BranchState::new(10);
        let (low, high) = ordered_pair(ForkClass::Management);
        assert!(matches!(
            state.resolve(4, high, low),
            BranchDecision::Orphaned(_)
        ));
        assert!(matches!(state.resolve(4, low, high), BranchDecision::Keep));
    }

    #[test]
    fn orphaned_is_sticky() {
        let mut orphaned = filled(0..=5).orphaned();
        assert!(orphaned.is_orphaned());
        assert!(orphaned.retain(6, sealed(6, 40)).is_err());
        assert!(orphaned.prepare_branch_switch(5).is_none());
        let (low, high) = ordered_pair(ForkClass::Removal);
        assert!(matches!(
            orphaned.resolve(5, low, high),
            BranchDecision::Orphaned(_)
        ));
        orphaned.settle_through(3);
        assert!(orphaned.is_orphaned());
        let decoded = BranchState::decode(&orphaned.encode()).unwrap();
        assert!(decoded.is_orphaned());
        assert_eq!(decoded, orphaned);
    }

    #[test]
    fn replay_after_a_switch_retains_from_the_next_epoch() {
        let state = filled(0..=9);
        let prepared = state.prepare_branch_switch(4).unwrap();
        assert!(state.prepare_branch_switch(10).is_none());
        let (snapshot, mut replay) = prepared.into_parts();
        assert_eq!(snapshot, sealed(4, 40));
        assert_eq!(replay.retained_epochs(), vec![0, 1, 2, 3, 4]);
        assert_eq!(replay.retained_bytes(), 5 * 40);
        // The fork-epoch snapshot is already held; replay starts above it.
        assert!(replay.retain(4, sealed(4, 40)).is_err());
        replay.retain(5, sealed(55, 40)).unwrap();
        assert_eq!(replay.snapshot(5), Some(&sealed(55, 40)[..]));
    }

    #[test]
    fn codec_round_trips_canonically() {
        let mut gapped = BranchState::new(3);
        gapped.retain(3, sealed(3, 1)).unwrap();
        gapped.retain(9, sealed(9, 300)).unwrap();
        let states = [
            BranchState::new(0),
            BranchState::new(u64::MAX - 1),
            filled(0..=70),
            gapped,
            filled(2..=4).orphaned(),
        ];
        for state in states {
            let bytes = state.encode();
            assert!(bytes.starts_with(b"DFBR\x01"));
            assert!(bytes.len() <= MAX_BRANCH_RECORD);
            let decoded = BranchState::decode(&bytes).unwrap();
            assert_eq!(decoded, state);
            assert_eq!(decoded.encode(), bytes);
        }
    }

    #[test]
    fn split_records_round_trip_and_must_match_their_header() {
        let mut gapped = BranchState::new(3);
        gapped.retain(3, sealed(3, 7)).unwrap();
        gapped.retain(9, sealed(9, 300)).unwrap();
        for state in [BranchState::new(5), filled(0..=70), gapped.clone(), filled(1..=3).orphaned()] {
            let meta = state.meta_record();
            assert!(meta.len() <= 5 + 11 + 64 * 8);
            let parts: Vec<_> = state.snapshots().map(|(e, s)| (e, s.to_vec())).collect();
            assert!(parts.iter().all(|(_, s)| s.len() <= MAX_BRANCH_SNAPSHOT));
            assert_eq!(BranchState::from_parts(&meta, &parts).unwrap(), state);
        }
        let meta = gapped.meta_record();
        let parts: Vec<_> = gapped.snapshots().map(|(e, s)| (e, s.to_vec())).collect();
        // A missing, an extra and a renamed snapshot are rejected.
        assert!(BranchState::from_parts(&meta, &parts[..1]).is_err());
        let mut extra = parts.clone();
        extra.push((10, vec![1]));
        assert!(BranchState::from_parts(&meta, &extra).is_err());
        let mut renamed = parts.clone();
        renamed[1].0 = 8;
        assert!(BranchState::from_parts(&meta, &renamed).is_err());
        // The bounds of the whole record still apply (settled epoch).
        let mut bad = meta.clone();
        bad[5..13].copy_from_slice(&4u64.to_be_bytes());
        assert!(BranchState::from_parts(&bad, &parts).is_err());
        assert!(BranchState::from_parts(b"DFBR\x01", &[]).is_err());
    }

    fn record(first_unsettled: u64, orphaned: u8, entries: &[(u64, Vec<u8>)]) -> Vec<u8> {
        let mut bytes = b"DFBR\x01".to_vec();
        bytes.extend(first_unsettled.to_be_bytes());
        bytes.push(orphaned);
        bytes.extend((entries.len() as u16).to_be_bytes());
        for (epoch, sealed) in entries {
            bytes.extend(epoch.to_be_bytes());
            bytes.extend((sealed.len() as u32).to_be_bytes());
            bytes.extend(sealed);
        }
        bytes
    }

    #[test]
    fn codec_rejects_bad_records() {
        let good = record(2, 0, &[(2, vec![1; 4]), (3, vec![2; 4])]);
        assert_eq!(
            BranchState::decode(&good).unwrap().retained_epochs(),
            vec![2, 3]
        );
        let mut cases: Vec<(&str, Vec<u8>)> = Vec::new();
        let mut wrong_magic = good.clone();
        wrong_magic[0] = b'X';
        cases.push(("wrong magic", wrong_magic));
        for version in [0, 2, 255] {
            let mut bytes = good.clone();
            bytes[4] = version;
            cases.push(("version", bytes));
        }
        let mut trailing = good.clone();
        trailing.push(0);
        cases.push(("trailing byte", trailing));
        cases.push(("truncated", good[..good.len() - 1].to_vec()));
        cases.push(("empty", Vec::new()));
        cases.push(("header only", good[..HEADER - 1].to_vec()));
        cases.push(("oversize", vec![0; MAX_BRANCH_RECORD + 1]));
        cases.push(("orphan byte", record(2, 2, &[])));
        cases.push(("orphaned with snapshots", record(2, 1, &[(2, vec![1; 4])])));
        cases.push((
            "repeated epoch",
            record(2, 0, &[(3, vec![1; 4]), (3, vec![1; 4])]),
        ));
        cases.push((
            "decreasing epoch",
            record(2, 0, &[(4, vec![1; 4]), (3, vec![1; 4])]),
        ));
        cases.push(("settled epoch", record(5, 0, &[(4, vec![1; 4])])));
        cases.push((
            "outside window",
            record(5, 0, &[(5 + ROLLBACK_EPOCHS, vec![1; 4])]),
        ));
        cases.push(("empty snapshot", record(2, 0, &[(2, Vec::new())])));
        let too_many: Vec<_> = (0..=ROLLBACK_EPOCHS)
            .map(|epoch| (epoch, vec![1]))
            .collect();
        cases.push(("too many", record(0, 0, &too_many)));
        // 63 snapshots, one byte over the bound; the record itself still fits
        // under MAX_BRANCH_RECORD, so the byte-bound check is what rejects it.
        let each = MAX_ROLLBACK_BYTES / 63;
        let mut big: Vec<_> = (0..63u64).map(|epoch| (epoch, vec![1; each])).collect();
        big[62].1 = vec![1; MAX_ROLLBACK_BYTES + 1 - 62 * each];
        let over = record(0, 0, &big);
        assert!(over.len() <= MAX_BRANCH_RECORD);
        cases.push(("over byte bound", over));
        cases.push((
            "snapshot over the limit",
            record(0, 0, &[(0, vec![1; MAX_BRANCH_SNAPSHOT + 1])]),
        ));
        let mut huge_length = record(2, 0, &[(2, vec![1; 4])]);
        huge_length[HEADER + 8..HEADER + 12].copy_from_slice(&u32::MAX.to_be_bytes());
        cases.push(("length past the end", huge_length));
        for (name, bytes) in cases {
            assert!(
                BranchState::decode(&bytes).is_err(),
                "{name} must be rejected"
            );
        }
    }
}
