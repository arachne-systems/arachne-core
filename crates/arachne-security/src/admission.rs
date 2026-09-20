use sha2::{Digest, Sha256};
use std::collections::{HashSet, VecDeque};

pub const MAX_ADMISSION_QUEUE_ITEMS: usize = 2048;
pub const MAX_ADMISSION_QUEUE_BYTES: usize = 32 * 1024 * 1024;

/// One authenticated admission request waiting for the owner transition.
/// The request bytes are the idempotency material; transport metadata does not
/// define whether two attempts are the same.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmissionAttempt {
    endpoint: [u8; 32],
    request: Vec<u8>,
}

impl AdmissionAttempt {
    pub fn new(endpoint: [u8; 32], request: Vec<u8>) -> Result<Self, &'static str> {
        if endpoint == [0; 32] || request.is_empty() {
            return Err("invalid admission attempt");
        }
        Ok(Self { endpoint, request })
    }

    pub fn endpoint(&self) -> [u8; 32] {
        self.endpoint
    }

    pub fn request(&self) -> &[u8] {
        &self.request
    }

    /// Stable within the workspace admission domain. The workspace scope is
    /// supplied by the queue owner, so this ID is not a global identity.
    pub fn id(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(b"data-fabric/admission-attempt/v1\0");
        digest.update(self.endpoint);
        digest.update(&self.request);
        digest.finalize().into()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionEnqueue {
    Added,
    Duplicate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionQueueError {
    Full,
    BytesExhausted,
}

/// Bounded owner-side intake. Cryptographic commits remain serialized by the
/// caller, while unrelated attempts can wait without blocking intake.
pub struct AdmissionQueue {
    items: VecDeque<AdmissionAttempt>,
    ids: HashSet<[u8; 32]>,
    bytes: usize,
    max_items: usize,
    max_bytes: usize,
}

impl AdmissionQueue {
    pub fn new() -> Self {
        Self::with_limits(MAX_ADMISSION_QUEUE_ITEMS, MAX_ADMISSION_QUEUE_BYTES)
    }

    pub fn with_limits(max_items: usize, max_bytes: usize) -> Self {
        Self {
            items: VecDeque::new(),
            ids: HashSet::new(),
            bytes: 0,
            max_items,
            max_bytes,
        }
    }

    pub fn enqueue(
        &mut self,
        attempt: AdmissionAttempt,
    ) -> Result<AdmissionEnqueue, AdmissionQueueError> {
        let id = attempt.id();
        if self.ids.contains(&id) {
            return Ok(AdmissionEnqueue::Duplicate);
        }
        if self.items.len() >= self.max_items {
            return Err(AdmissionQueueError::Full);
        }
        let bytes = attempt.request.len();
        if bytes > self.max_bytes.saturating_sub(self.bytes) {
            return Err(AdmissionQueueError::BytesExhausted);
        }
        self.bytes += bytes;
        self.ids.insert(id);
        self.items.push_back(attempt);
        Ok(AdmissionEnqueue::Added)
    }

    pub fn contains(&self, attempt: &AdmissionAttempt) -> bool {
        self.ids.contains(&attempt.id())
    }

    pub fn pop(&mut self) -> Option<AdmissionAttempt> {
        let attempt = self.items.pop_front()?;
        self.bytes -= attempt.request.len();
        let id = attempt.id();
        self.ids.remove(&id);
        Some(attempt)
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn bytes(&self) -> usize {
        self.bytes
    }
}

impl Default for AdmissionQueue {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attempt(endpoint: u8, request: u8) -> AdmissionAttempt {
        AdmissionAttempt::new([endpoint; 32], vec![request; 4]).unwrap()
    }

    #[test]
    fn duplicate_is_idempotent_but_new_request_from_same_endpoint_is_not() {
        let mut queue = AdmissionQueue::with_limits(4, 32);
        assert_eq!(queue.enqueue(attempt(1, 1)), Ok(AdmissionEnqueue::Added));
        assert_eq!(
            queue.enqueue(attempt(1, 1)),
            Ok(AdmissionEnqueue::Duplicate)
        );
        assert_eq!(queue.enqueue(attempt(1, 2)), Ok(AdmissionEnqueue::Added));
        assert_eq!(queue.len(), 2);
    }

    #[test]
    fn item_and_byte_bounds_fail_closed() {
        let mut queue = AdmissionQueue::with_limits(1, 4);
        assert_eq!(queue.enqueue(attempt(1, 1)), Ok(AdmissionEnqueue::Added));
        assert_eq!(queue.enqueue(attempt(2, 2)), Err(AdmissionQueueError::Full));
        assert_eq!(queue.pop().unwrap().endpoint(), [1; 32]);
        assert_eq!(queue.enqueue(attempt(2, 2)), Ok(AdmissionEnqueue::Added));
        assert_eq!(queue.enqueue(attempt(3, 3)), Err(AdmissionQueueError::Full));
    }
}
