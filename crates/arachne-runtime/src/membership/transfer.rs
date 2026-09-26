//! Bounded, content-addressed fragments for membership steps and order proofs.
//! A reference selects bytes. The membership verifier still decides authority.
use super::*;
use arachne_node::{ControlClient, Error};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const REFERENCE: &[u8] = b"DFRF\x01";
pub(crate) const QUERY: &[u8] = b"DFFQ\x01";
const REPLY: &[u8] = b"DFFP\x01";
pub(crate) const FRAGMENT_BYTES: usize = 96 * 1024;
pub(crate) const RESOLVED_PAGE_BYTES: usize = MAX_WIRE_STEP + arachne_node::MAX_CONTROL_REPLY;
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(30);
pub(crate) type Orders = BTreeMap<[u8; 32], Arc<[u8]>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Object {
    Step(u64),
    Order([u8; 32]),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Reference {
    pub workspace: [u8; 32],
    pub object: Object,
    length: u32,
    digest: [u8; 32],
}

impl Reference {
    pub(crate) fn new(workspace: [u8; 32], object: Object, bytes: &[u8]) -> Result<Self, Error> {
        if bytes.is_empty() || bytes.len() > MAX_WIRE_STEP {
            return Err(Error::TooLarge);
        }
        Ok(Self {
            workspace,
            object,
            length: bytes.len() as u32,
            digest: Sha256::digest(bytes).into(),
        })
    }
    fn validate(&self) -> Result<(), Error> {
        if self.length == 0 || self.length as usize > MAX_WIRE_STEP {
            return Err(Error::TooLarge);
        }
        Ok(())
    }
    pub(crate) fn encode(&self) -> Result<Vec<u8>, Error> {
        encode(REFERENCE, self, 160)
    }
}

pub(crate) fn is_reference(bytes: &[u8]) -> bool {
    bytes.starts_with(b"DFRF")
}
pub(crate) fn decode_reference(bytes: &[u8]) -> Result<Reference, Error> {
    let value: Reference = decode(REFERENCE, bytes, 160)?;
    value.validate()?;
    Ok(value)
}

#[derive(Serialize, Deserialize)]
struct Query {
    reference: Reference,
    offset: u32,
}
#[derive(Serialize, Deserialize)]
struct Fragment<'a> {
    reference: Reference,
    offset: u32,
    #[serde(borrow)]
    bytes: &'a [u8],
}

fn encode(prefix: &[u8], value: &impl Serialize, limit: usize) -> Result<Vec<u8>, Error> {
    let mut bytes = prefix.to_vec();
    bytes.extend(postcard::to_allocvec(value).map_err(|_| Error::InvalidFrame)?);
    if bytes.len() > limit {
        return Err(Error::TooLarge);
    }
    Ok(bytes)
}
fn decode<'a, T: Deserialize<'a>>(
    prefix: &[u8],
    bytes: &'a [u8],
    limit: usize,
) -> Result<T, Error> {
    if bytes.len() > limit {
        return Err(Error::TooLarge);
    }
    let body = bytes.strip_prefix(prefix).ok_or(Error::InvalidFrame)?;
    let (value, rest) = postcard::take_from_bytes(body).map_err(|_| Error::InvalidFrame)?;
    if !rest.is_empty() {
        return Err(Error::InvalidFrame);
    }
    Ok(value)
}

/// Refusal is empty. The authenticated peer may read current-member history,
/// or its exact terminal removal step, through the existing security rule.
pub(crate) fn reply(
    owner: Option<&arachne_security::Workspace>,
    orders: &Orders,
    peer: [u8; 32],
    packet: &[u8],
) -> Vec<u8> {
    let answer = || -> Result<Vec<u8>, Error> {
        let owner = owner.ok_or(Error::Rejected)?;
        let query: Query = decode(QUERY, packet, 192)?;
        query.reference.validate()?;
        if query.reference.workspace != owner.id() {
            return Err(Error::Rejected);
        }
        let bytes: std::borrow::Cow<'_, [u8]> = match query.reference.object {
            Object::Step(after) => {
                let (auth, commit) = owner
                    .membership_update_for(peer, after)
                    .map_err(|_| Error::Rejected)?
                    .ok_or(Error::Rejected)?;
                std::borrow::Cow::Owned(encode_step(&auth, &commit).map_err(|_| Error::TooLarge)?)
            }
            Object::Order(id) => {
                owner
                    .member_id_for_endpoint(peer)
                    .map_err(|_| Error::Rejected)?;
                std::borrow::Cow::Borrowed(orders.get(&id).ok_or(Error::Rejected)?)
            }
        };
        fragment(&query, &bytes)
    };
    answer().unwrap_or_default()
}

fn fragment(query: &Query, bytes: &[u8]) -> Result<Vec<u8>, Error> {
    if Reference::new(query.reference.workspace, query.reference.object, bytes)? != query.reference
    {
        return Err(Error::Rejected);
    }
    let offset = query.offset as usize;
    if offset >= bytes.len() {
        return Err(Error::InvalidFrame);
    }
    let end = (offset + FRAGMENT_BYTES).min(bytes.len());
    encode(
        REPLY,
        &Fragment {
            reference: query.reference,
            offset: query.offset,
            bytes: &bytes[offset..end],
        },
        arachne_node::MAX_CONTROL_REPLY,
    )
}

fn append(reference: Reference, bytes: &mut Vec<u8>, packet: &[u8]) -> Result<(), Error> {
    let fragment: Fragment<'_> = decode(REPLY, packet, arachne_node::MAX_CONTROL_REPLY)?;
    if fragment.reference != reference
        || fragment.offset as usize != bytes.len()
        || fragment.bytes.is_empty()
        || fragment.bytes.len() > FRAGMENT_BYTES
        || bytes.len().saturating_add(fragment.bytes.len()) > reference.length as usize
    {
        return Err(Error::InvalidFrame);
    }
    bytes.extend(fragment.bytes);
    if bytes.len() == reference.length as usize
        && Sha256::digest(&*bytes).as_slice() != reference.digest
    {
        return Err(Error::InvalidFrame);
    }
    Ok(())
}

async fn fetch_with<F, Fut>(reference: Reference, mut request: F) -> Result<Vec<u8>, Error>
where
    F: FnMut(Vec<u8>) -> Fut,
    Fut: std::future::Future<Output = Result<Vec<u8>, Error>>,
{
    reference.validate()?;
    let mut bytes = Vec::with_capacity(reference.length as usize);
    // Even a peer that sends one byte per reply gets a bounded request count.
    let pages = (reference.length as usize).div_ceil(FRAGMENT_BYTES);
    for _ in 0..pages {
        let query = encode(
            QUERY,
            &Query {
                reference,
                offset: bytes.len() as u32,
            },
            192,
        )?;
        let reply = request(query).await?;
        append(reference, &mut bytes, &reply)?;
        if bytes.len() == reference.length as usize {
            return Ok(bytes);
        }
    }
    Err(Error::InvalidFrame)
}

pub(crate) async fn fetch(
    client: ControlClient,
    peer: [u8; 32],
    reference: Reference,
) -> Result<Vec<u8>, Error> {
    tokio::time::timeout(
        TRANSFER_TIMEOUT,
        fetch_with(reference, |query| {
            let client = client.clone();
            async move { client.request_control(peer, &query).await }
        }),
    )
    .await
    .map_err(|_| Error::Timeout("membership proof fragments"))?
}

/// A page holds at most one large object. All other bytes fit the ordinary
/// control reply. This bounds expansion before any allocation or request.
pub(crate) async fn resolve_steps(
    client: ControlClient,
    peer: [u8; 32],
    workspace: [u8; 32],
    steps: &[&[u8]],
    wire_steps: bool,
) -> Result<Vec<Vec<u8>>, Error> {
    let mut referenced = None;
    let mut bytes = 0usize;
    for (index, step) in steps.iter().enumerate() {
        if is_reference(step) {
            let reference = decode_reference(step)?;
            if reference.workspace != workspace
                || !matches!(reference.object, Object::Step(_))
                || referenced.replace((index, reference)).is_some()
            {
                return Err(Error::InvalidFrame);
            }
            bytes = bytes.saturating_add(reference.length as usize + 16);
        } else {
            bytes = bytes.saturating_add(step.len());
        }
    }
    if bytes > RESOLVED_PAGE_BYTES {
        return Err(Error::TooLarge);
    }
    let fetched = if let Some((_, reference)) = referenced {
        Some(fetch(client, peer, reference).await?)
    } else {
        None
    };
    steps
        .iter()
        .enumerate()
        .map(|(index, step)| {
            if referenced.is_some_and(|(at, _)| at == index) {
                let bytes = fetched.as_ref().unwrap();
                if wire_steps {
                    super::wire_step(bytes, None, usize::MAX).map_err(|_| Error::InvalidFrame)
                } else {
                    Ok(bytes.clone())
                }
            } else {
                Ok(step.to_vec())
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fragments_reassemble_a_proof_above_the_control_reply_bound() {
        let bytes = vec![37; 7 * FRAGMENT_BYTES + 23];
        let reference = Reference::new([1; 32], Object::Step(23), &bytes).unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = runtime
            .block_on(fetch_with(reference, |query| {
                let query: Query = decode(QUERY, &query, 192).unwrap();
                let page = fragment(&query, &bytes).unwrap();
                assert!(page.len() <= arachne_node::MAX_CONTROL_REPLY);
                async { Ok(page) }
            }))
            .unwrap();
        assert_eq!(result, bytes);
    }
    #[test]
    fn fragment_bounds_reject_wrong_offsets_lengths_hashes_and_trailing_bytes() {
        let bytes = vec![5; FRAGMENT_BYTES + 1];
        let reference = Reference::new([1; 32], Object::Step(1), &bytes).unwrap();
        let page = fragment(
            &Query {
                reference,
                offset: 0,
            },
            &bytes,
        )
        .unwrap();
        let mut buffer = Vec::new();
        append(reference, &mut buffer, &page).unwrap();
        assert!(append(reference, &mut buffer, &page).is_err());
        let packet = |offset, body: &[u8]| {
            encode(
                REPLY,
                &Fragment {
                    reference,
                    offset,
                    bytes: body,
                },
                arachne_node::MAX_CONTROL_REPLY,
            )
            .unwrap()
        };
        assert!(append(reference, &mut buffer, &packet(1, &[5])).is_err());
        assert!(append(reference, &mut buffer, &packet(FRAGMENT_BYTES as u32, &[])).is_err());
        assert!(
            append(
                reference,
                &mut buffer,
                &packet(FRAGMENT_BYTES as u32, &[5, 5])
            )
            .is_err()
        );
        assert!(
            append(
                reference,
                &mut buffer.clone(),
                &packet(FRAGMENT_BYTES as u32, &[9])
            )
            .is_err()
        );
        let mut trailing = packet(FRAGMENT_BYTES as u32, &[5]);
        trailing.push(0);
        assert!(append(reference, &mut buffer.clone(), &trailing).is_err());
        assert!(
            fragment(
                &Query {
                    reference,
                    offset: bytes.len() as u32
                },
                &bytes
            )
            .is_err()
        );
        let forged = Reference {
            length: MAX_WIRE_STEP as u32 + 1,
            ..reference
        };
        assert!(decode_reference(&forged.encode().unwrap()).is_err());
        append(reference, &mut buffer, &packet(FRAGMENT_BYTES as u32, &[5])).unwrap();
        assert_eq!(buffer, bytes);
    }
    #[test]
    fn fragment_serving_keeps_member_and_terminal_step_authorization() {
        let (owner, members, endpoints) = super::super::admit_members(213, "Fragment member", 2);
        let after = owner.epoch();
        let removed = owner
            .prepare_management(arachne_security::ManagementAction::Remove(
                members[0].member().unwrap().id(),
            ))
            .unwrap();
        let raw = encode_step(&removed.authorization, &removed.commit).unwrap();
        let reference = Reference::new(owner.id(), Object::Step(after), &raw).unwrap();
        let query = encode(
            QUERY,
            &Query {
                reference,
                offset: 0,
            },
            192,
        )
        .unwrap();
        let orders = Orders::new();
        assert!(!reply(Some(&removed.workspace), &orders, endpoints[0], &query).is_empty());
        assert!(!reply(Some(&removed.workspace), &orders, endpoints[1], &query).is_empty());
        assert!(reply(Some(&removed.workspace), &orders, [99; 32], &query).is_empty());
        let other = Reference {
            workspace: [0; 32],
            ..reference
        };
        let query = encode(
            QUERY,
            &Query {
                reference: other,
                offset: 0,
            },
            192,
        )
        .unwrap();
        assert!(reply(Some(&removed.workspace), &orders, endpoints[1], &query).is_empty());
        let changed = Reference {
            digest: [0; 32],
            ..reference
        };
        let query = encode(
            QUERY,
            &Query {
                reference: changed,
                offset: 0,
            },
            192,
        )
        .unwrap();
        assert!(reply(Some(&removed.workspace), &orders, endpoints[1], &query).is_empty());
        let earlier = owner
            .membership_update_for(endpoints[1], after - 1)
            .unwrap()
            .unwrap();
        let raw = encode_step(&earlier.0, &earlier.1).unwrap();
        let reference = Reference::new(owner.id(), Object::Step(after - 1), &raw).unwrap();
        let query = encode(
            QUERY,
            &Query {
                reference,
                offset: 0,
            },
            192,
        )
        .unwrap();
        assert!(reply(Some(&removed.workspace), &orders, endpoints[0], &query).is_empty());
    }
    #[test]
    fn multiple_or_wrong_workspace_references_fail_before_fetch() {
        let (owner, _, _) = super::super::admit_members(214, "Fragment member", 1);
        let session = super::super::bare_test_session(owner);
        let workspace = session.workspace.as_ref().unwrap().id();
        let reference = Reference::new(workspace, Object::Step(1), &[1; 16])
            .unwrap()
            .encode()
            .unwrap();
        let result = session.runtime.block_on(resolve_steps(
            session.node.control_client(),
            [9; 32],
            workspace,
            &[&reference, &reference],
            false,
        ));
        assert!(matches!(result, Err(Error::InvalidFrame)));
        let result = session.runtime.block_on(resolve_steps(
            session.node.control_client(),
            [9; 32],
            [7; 32],
            &[&reference],
            false,
        ));
        assert!(matches!(result, Err(Error::InvalidFrame)));
        let too_much = vec![0; RESOLVED_PAGE_BYTES + 1];
        let result = session.runtime.block_on(resolve_steps(
            session.node.control_client(),
            [9; 32],
            workspace,
            &[&too_much],
            false,
        ));
        assert!(matches!(result, Err(Error::TooLarge)));
    }
    #[test]
    fn short_fragments_cannot_amplify_the_page_count() {
        let bytes = vec![4; FRAGMENT_BYTES + 1];
        let reference = Reference::new([1; 32], Object::Step(1), &bytes).unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut count = 0;
        let result = runtime.block_on(fetch_with(reference, |query| {
            count += 1;
            let query: Query = decode(QUERY, &query, 192).unwrap();
            let page = encode(
                REPLY,
                &Fragment {
                    reference,
                    offset: query.offset,
                    bytes: &[4],
                },
                arachne_node::MAX_CONTROL_REPLY,
            )
            .unwrap();
            async { Ok(page) }
        }));
        assert!(result.is_err());
        assert_eq!(count, 2);
    }
}
