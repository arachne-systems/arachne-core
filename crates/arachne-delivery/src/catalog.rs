//! Transport-neutral catalog entry envelope.
//!
//! The topic supplies the catalog namespace (for example feeds or resources);
//! the payload remains owned by the application adapter. Current-value delivery
//! supplies replication, replacement and expiry semantics around this envelope.

use arachne_security::MAX_APPLICATION_PAYLOAD;

const MAGIC: &[u8; 5] = b"DFCE\x01";
const HEADER: usize = 5 + 32 + 1 + 4;
pub const MAX_CATALOG_PAYLOAD: usize = MAX_APPLICATION_PAYLOAD - HEADER;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CatalogEntry {
    pub key: [u8; 32],
    pub payload: Vec<u8>,
    pub tombstone: bool,
}

impl CatalogEntry {
    pub fn to_wire(&self) -> Result<Vec<u8>, &'static str> {
        if self.tombstone && !self.payload.is_empty() {
            return Err("catalog tombstone has payload");
        }
        if !self.tombstone
            && (self.payload.is_empty() || self.payload.len() > MAX_CATALOG_PAYLOAD)
        {
            return Err("catalog entry payload is out of bounds");
        }
        let mut bytes = MAGIC.to_vec();
        bytes.extend(self.key);
        bytes.push(self.tombstone.into());
        bytes.extend((self.payload.len() as u32).to_be_bytes());
        bytes.extend(&self.payload);
        Ok(bytes)
    }

    pub fn from_wire(mut bytes: &[u8]) -> Result<Self, &'static str> {
        if take(&mut bytes, 5)? != MAGIC {
            return Err("wrong catalog entry format");
        }
        let key = take(&mut bytes, 32)?.try_into().unwrap();
        let tombstone = match take(&mut bytes, 1)?[0] {
            0 => false,
            1 => true,
            _ => return Err("invalid catalog tombstone"),
        };
        let length = u32::from_be_bytes(take(&mut bytes, 4)?.try_into().unwrap()) as usize;
        let payload = take(&mut bytes, length)?.to_vec();
        if !bytes.is_empty() {
            return Err("trailing catalog entry");
        }
        let entry = Self {
            key,
            payload,
            tombstone,
        };
        entry.to_wire()?;
        Ok(entry)
    }
}

fn take<'a>(input: &mut &'a [u8], length: usize) -> Result<&'a [u8], &'static str> {
    if input.len() < length {
        return Err("truncated catalog entry");
    }
    let (head, tail) = input.split_at(length);
    *input = tail;
    Ok(head)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_entry_round_trips_and_tombstones_are_empty() {
        let entry = CatalogEntry {
            key: [7; 32],
            payload: b"feed-v1".to_vec(),
            tombstone: false,
        };
        assert_eq!(
            CatalogEntry::from_wire(&entry.to_wire().unwrap()).unwrap(),
            entry
        );
        let tombstone = CatalogEntry {
            key: [8; 32],
            payload: Vec::new(),
            tombstone: true,
        };
        assert_eq!(
            CatalogEntry::from_wire(&tombstone.to_wire().unwrap()).unwrap(),
            tombstone
        );
        assert!(
            CatalogEntry {
                key: [0; 32],
                payload: vec![1],
                tombstone: true
            }
            .to_wire()
            .is_err()
        );
    }
}
