//! Canonical routing metadata. Authentication remains the security owner's job.
use super::{Topic, WorkspaceId};

/// Stable across retransmission. The caller supplies a fresh ID for a new
/// publication; neither a timestamp nor payload equality is an identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicationContext {
    pub workspace: WorkspaceId,
    pub revision: u64,
    pub topic: Topic,
    pub id: [u8; 16],
    /// Publisher retention order within the authenticated author's workspace
    /// epoch. None denotes legacy data; this is not an MLS generation or receipt.
    pub sequence: Option<std::num::NonZeroU64>,
}

impl PublicationContext {
    /// Versioned, unambiguous AAD for the security module. Every routing value
    /// comes from the expected received envelope, never from unchecked MLS AAD.
    pub fn authenticated_bytes(&self) -> Vec<u8> {
        let mut bytes = if self.sequence.is_some() {
            b"data-fabric/publication/v2\0".to_vec()
        } else {
            b"data-fabric/publication/v1\0".to_vec()
        };
        bytes.extend(self.workspace);
        bytes.extend(self.revision.to_be_bytes());
        bytes.push(self.topic.as_str().len() as u8); // Topic bounds length to128.
        bytes.extend(self.topic.as_str().as_bytes());
        bytes.extend(self.id);
        if let Some(sequence) = self.sequence {
            bytes.extend(sequence.get().to_be_bytes());
        }
        bytes
    }

    /// Recipient membership identities are authenticated separately from the
    /// transport endpoint fanout. The caller must require a nonempty, sorted,
    /// unique scope before using this form.
    pub fn direct_authenticated_bytes(
        &self,
        recipients: &[[u8; 32]],
    ) -> Result<Vec<u8>, &'static str> {
        if recipients.is_empty()
            || recipients.len() > 64
            || recipients.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err("invalid direct recipient scope");
        }
        let mut bytes = b"data-fabric/direct-publication/v1\0".to_vec();
        bytes.extend(self.authenticated_bytes());
        bytes.push(recipients.len() as u8);
        for recipient in recipients {
            bytes.extend(recipient);
        }
        Ok(bytes)
    }

    /// Small packet carried as Node's opaque payload. Routing fields are already
    /// in the outer Node frame; the recipient reconstructs this context from it.
    pub fn packet(&self, ciphertext: &[u8]) -> Result<Vec<u8>, &'static str> {
        let header = if self.sequence.is_some() { 29 } else { 21 };
        if ciphertext.is_empty() || ciphertext.len() > 16 * 1024 - header {
            return Err("protected packet exceeds bounds");
        }
        let mut packet = if self.sequence.is_some() {
            b"DFAP\x02".to_vec()
        } else {
            b"DFAP\x01".to_vec()
        };
        packet.extend(self.id);
        if let Some(sequence) = self.sequence {
            packet.extend(sequence.get().to_be_bytes());
        }
        packet.extend(ciphertext);
        Ok(packet)
    }

    pub fn unpack(
        workspace: WorkspaceId,
        revision: u64,
        topic: Topic,
        packet: &[u8],
    ) -> Result<(Self, &[u8]), &'static str> {
        if !(22..=16 * 1024).contains(&packet.len()) {
            return Err("invalid protected packet");
        }
        let (sequence, header) = match &packet[..5] {
            b"DFAP\x01" => (None, 21),
            b"DFAP\x02" if packet.len() >= 30 => (
                Some(
                    std::num::NonZeroU64::new(u64::from_be_bytes(
                        packet[21..29].try_into().unwrap(),
                    ))
                    .ok_or("zero publisher sequence")?,
                ),
                29,
            ),
            _ => return Err("invalid protected packet"),
        };
        Ok((
            Self {
                sequence,
                workspace,
                revision,
                topic,
                id: packet[5..21].try_into().unwrap(),
            },
            &packet[header..],
        ))
    }
}

#[test]
fn publication_context_has_unambiguous_boundaries() {
    let original = PublicationContext {
        sequence: None,
        workspace: [1; 32],
        revision: 7,
        topic: Topic::new("streams/sample").unwrap(),
        id: [2; 16],
    };
    let bytes = original.authenticated_bytes();
    let mut changed = original.clone();
    changed.revision += 1;
    assert_ne!(bytes, changed.authenticated_bytes());
    changed = original.clone();
    changed.workspace[0] ^= 1;
    assert_ne!(bytes, changed.authenticated_bytes());
    changed = original.clone();
    changed.id[0] ^= 1;
    assert_ne!(bytes, changed.authenticated_bytes());
    changed = original.clone();
    changed.topic = Topic::new("streams/other").unwrap();
    assert_ne!(bytes, changed.authenticated_bytes());
    let packet = original.packet(&[0, 255, 7]).unwrap();
    let (decoded, ciphertext) = PublicationContext::unpack(
        original.workspace,
        original.revision,
        original.topic.clone(),
        &packet,
    )
    .unwrap();
    assert_eq!(decoded, original);
    assert_eq!(ciphertext, &[0, 255, 7]);
    for length in 0..22 {
        assert!(
            PublicationContext::unpack(
                original.workspace,
                7,
                original.topic.clone(),
                &packet[..length]
            )
            .is_err()
        );
    }
    assert!(original.packet(&[]).is_err());
    assert!(original.packet(&vec![0; 16 * 1024]).is_err());
}

#[test]
fn sequenced_packets_preserve_legacy_and_bind_order() {
    let mut context = PublicationContext {
        workspace: [1; 32],
        revision: 2,
        topic: Topic::new("streams/sample").unwrap(),
        id: [3; 16],
        sequence: None,
    };
    let legacy = context.packet(&[7]).unwrap();
    assert_eq!(&legacy[..5], b"DFAP\x01");
    let legacy_aad = context.authenticated_bytes();
    context.sequence = std::num::NonZeroU64::new(1);
    let aad = context.authenticated_bytes();
    assert_ne!(aad, legacy_aad);
    let packet = context.packet(&[7]).unwrap();
    assert_eq!(&packet[..5], b"DFAP\x02");
    let decode = |p: &[u8]| {
        PublicationContext::unpack(
            context.workspace,
            context.revision,
            context.topic.clone(),
            p,
        )
        .map(|(c, _)| c)
    };
    assert_eq!(decode(&packet).unwrap(), context);
    assert_eq!(decode(&legacy).unwrap().sequence, None);
    context.sequence = std::num::NonZeroU64::new(u64::MAX);
    assert_ne!(context.authenticated_bytes(), aad);
    let max = context.packet(&vec![7; 16 * 1024 - 29]).unwrap();
    assert_eq!(max.len(), 16 * 1024);
    assert!(context.packet(&vec![7; 16 * 1024 - 28]).is_err());
    for length in 0..30 {
        assert!(
            PublicationContext::unpack(
                context.workspace,
                context.revision,
                context.topic.clone(),
                &packet[..length]
            )
            .is_err()
        );
    }
    let mut zero = packet;
    zero[21..29].fill(0);
    assert!(
        PublicationContext::unpack(
            context.workspace,
            context.revision,
            context.topic.clone(),
            &zero
        )
        .is_err()
    );
}

#[test]
fn direct_scope_is_canonical_and_authenticated() {
    let context = PublicationContext {
        workspace: [1; 32],
        revision: 2,
        topic: Topic::new("chat").unwrap(),
        id: [3; 16],
        sequence: None,
    };
    let audience = vec![[4; 32], [5; 32]];
    let bytes = context.direct_authenticated_bytes(&audience).unwrap();
    assert_ne!(bytes, context.authenticated_bytes());
    assert_ne!(
        bytes,
        context
            .direct_authenticated_bytes(&[[4; 32], [6; 32]])
            .unwrap()
    );
    // The recipient count and identities must actually bind the audience: a
    // 1-recipient scope and a 2-recipient scope sharing the first recipient
    // must diverge, and identical recipient lists must produce identical bytes.
    assert_ne!(
        context.direct_authenticated_bytes(&[[4; 32]]).unwrap(),
        context
            .direct_authenticated_bytes(&[[4; 32], [5; 32]])
            .unwrap()
    );
    assert_eq!(
        context.direct_authenticated_bytes(&[[4; 32], [5; 32]]).unwrap(),
        context
            .direct_authenticated_bytes(&[[4; 32], [5; 32]])
            .unwrap()
    );
    assert!(context.direct_authenticated_bytes(&[]).is_err());
    assert!(
        context
            .direct_authenticated_bytes(&[[5; 32], [4; 32]])
            .is_err()
    );
    assert!(
        context
            .direct_authenticated_bytes(&[[4; 32], [4; 32]])
            .is_err()
    );
}
