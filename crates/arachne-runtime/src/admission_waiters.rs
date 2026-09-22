//! Waiting admission exchanges: a requester's open fabric exchange, held until
//! its admission attempt has a result. Only a faster delivery of the retained
//! result. Dropping one loses nothing; the requester asks again.
use std::collections::BTreeMap;

pub(super) trait HeldExchange {
    fn expired(&self) -> bool;
}

impl HeldExchange for arachne_node::ControlRequest {
    fn expired(&self) -> bool {
        arachne_node::ControlRequest::expired(self)
    }
}

pub(super) struct AdmissionWaiters<E> {
    held: BTreeMap<[u8; 32], (E, Option<Vec<u8>>)>,
    limit: usize,
}

impl<E: HeldExchange> AdmissionWaiters<E> {
    pub(super) fn new(limit: usize) -> Self {
        Self {
            held: BTreeMap::new(),
            limit,
        }
    }

    /// Hold the exchange. A second ask for the same attempt replaces the first.
    /// At the bound the exchange comes back, and the caller answers
    /// `admission_queued` exactly as before this module existed.
    pub(super) fn hold(
        &mut self,
        attempt: [u8; 32],
        exchange: E,
        checkpoint: Option<Vec<u8>>,
    ) -> Option<E> {
        if !self.held.contains_key(&attempt) && self.held.len() >= self.limit {
            // The transport ended these at its own deadline. No timer of ours.
            self.held.retain(|_, (held, _)| !held.expired());
            if self.held.len() >= self.limit {
                return Some(exchange);
            }
        }
        self.held.insert(attempt, (exchange, checkpoint));
        None
    }

    #[cfg(test)]
    pub(super) fn release(&mut self, attempt: &[u8; 32]) -> Option<(E, Option<Vec<u8>>)> {
        self.held
            .remove(attempt)
            .filter(|(exchange, _)| !exchange.expired())
    }

    /// Remove an exchange even when its requester has already closed it. The
    /// runtime uses that last observation to reuse the requester's route for a
    /// pushed retained result.
    pub(super) fn take(&mut self, attempt: &[u8; 32]) -> Option<(E, Option<Vec<u8>>)> {
        self.held.remove(attempt)
    }

    pub(super) fn len(&self) -> usize {
        self.held.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::rc::Rc;

    struct Fake(Rc<Cell<bool>>, u8);
    impl HeldExchange for Fake {
        fn expired(&self) -> bool {
            self.0.get()
        }
    }
    fn live(tag: u8) -> (Fake, Rc<Cell<bool>>) {
        let expired = Rc::new(Cell::new(false));
        (Fake(Rc::clone(&expired), tag), expired)
    }

    #[test]
    fn holds_up_to_the_limit_then_hands_the_exchange_back() {
        let mut waiters = AdmissionWaiters::new(2);
        assert!(waiters.hold([1; 32], live(1).0, None).is_none());
        assert!(waiters.hold([2; 32], live(2).0, Some(vec![9])).is_none());
        let overflow = waiters.hold([3; 32], live(3).0, None);
        assert_eq!(overflow.map(|fake| fake.1), Some(3));
        assert_eq!(waiters.len(), 2);
    }

    #[test]
    fn a_second_ask_for_the_same_attempt_replaces_the_first() {
        let mut waiters = AdmissionWaiters::new(1);
        assert!(waiters.hold([1; 32], live(1).0, None).is_none());
        assert!(waiters.hold([1; 32], live(2).0, None).is_none());
        let (exchange, _) = waiters.release(&[1; 32]).unwrap();
        assert_eq!(exchange.1, 2);
    }

    #[test]
    fn expired_exchanges_free_their_slot_without_a_timer() {
        let mut waiters = AdmissionWaiters::new(1);
        let (first, expired) = live(1);
        assert!(waiters.hold([1; 32], first, None).is_none());
        expired.set(true);
        assert!(waiters.hold([2; 32], live(2).0, None).is_none());
        assert!(waiters.release(&[1; 32]).is_none());
        assert_eq!(waiters.len(), 1);
    }

    #[test]
    fn release_returns_the_checkpoint_and_skips_an_expired_exchange() {
        let mut waiters = AdmissionWaiters::new(2);
        let (gone, expired) = live(1);
        waiters.hold([1; 32], gone, None);
        waiters.hold([2; 32], live(2).0, Some(vec![7, 7]));
        expired.set(true);
        assert!(waiters.release(&[1; 32]).is_none());
        let (_, checkpoint) = waiters.release(&[2; 32]).unwrap();
        assert_eq!(checkpoint, Some(vec![7, 7]));
    }
}
