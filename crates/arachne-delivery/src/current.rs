//! Authenticated, bounded current views for opaque latest-value publications.

use arachne_routing::{PublicationContext, Topic};
use arachne_security::{MAX_APPLICATION_CIPHERTEXT, Workspace};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const MANIFEST: &[u8] = b"DFCV\x01";
const TOMBSTONE_MANIFEST: &[u8] = b"DFCV\x02";
const INDEX: &[u8] = b"DFCI\x01";
const TOMBSTONE_INDEX: &[u8] = b"DFCI\x02";
const QUERY: &[u8] = b"DFVQ\x01";
const REPLY: &[u8] = b"DFVR\x01";
const LIVE: &[u8] = b"DFVL\x01";
const TOMBSTONE_LIVE: &[u8] = b"DFVL\x02";
pub const MAX_CURRENT_VALUES: usize = 64;
pub const MAX_CURRENT_SELECTIONS: usize = 64;
const ENTRY_BYTES: usize = 96;
const TOMBSTONE_ENTRY_BYTES: usize = ENTRY_BYTES + 1;
const MAX_PACKET_BYTES: usize = super::wire::MAX_REPLY_BYTES - MAX_APPLICATION_CIPHERTEXT;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CurrentMetadata {
    pub selector: [u8; 32],
    pub replacement_key: [u8; 32],
    pub expires_at: u64,
    pub tombstone: bool,
}

impl CurrentMetadata {
    pub fn authenticated_context(&self, context: &PublicationContext) -> Vec<u8> {
        let mut bytes = if self.tombstone {
            b"data-fabric/live-current/v2\0".to_vec()
        } else {
            b"data-fabric/live-current/v1\0".to_vec()
        };
        bytes.extend(context.authenticated_bytes());
        bytes.extend(self.selector);
        bytes.extend(self.replacement_key);
        bytes.extend(self.expires_at.to_be_bytes());
        if self.tombstone {
            bytes.push(1);
        }
        bytes
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveCurrentPacket {
    pub metadata: CurrentMetadata,
    pub packet: Vec<u8>,
}

impl LiveCurrentPacket {
    pub fn to_wire(&self) -> Result<Vec<u8>, &'static str> {
        if self.metadata.expires_at == 0 || !(22..=16 * 1024).contains(&self.packet.len()) {
            return Err("invalid live current packet");
        }
        let mut bytes = if self.metadata.tombstone {
            TOMBSTONE_LIVE.to_vec()
        } else {
            LIVE.to_vec()
        };
        bytes.extend(self.metadata.selector);
        bytes.extend(self.metadata.replacement_key);
        bytes.extend(self.metadata.expires_at.to_be_bytes());
        if self.metadata.tombstone {
            bytes.push(1);
        }
        bytes.extend((self.packet.len() as u32).to_be_bytes());
        bytes.extend(&self.packet);
        Ok(bytes)
    }

    pub fn from_wire(bytes: &[u8]) -> Result<Self, &'static str> {
        let mut input = bytes;
        let format = take(&mut input, 5)?;
        if format != LIVE && format != TOMBSTONE_LIVE {
            return Err("wrong live current format");
        }
        let metadata = CurrentMetadata {
            selector: take(&mut input, 32)?.try_into().unwrap(),
            replacement_key: take(&mut input, 32)?.try_into().unwrap(),
            expires_at: number64(&mut input)?,
            tombstone: if format == TOMBSTONE_LIVE {
                match take(&mut input, 1)?[0] {
                    1 => true,
                    _ => return Err("invalid current tombstone"),
                }
            } else {
                false
            },
        };
        let length = number32(&mut input)?;
        if metadata.expires_at == 0 || !(22..=16 * 1024).contains(&length) {
            return Err("invalid live current packet");
        }
        let packet = take(&mut input, length)?.to_vec();
        if !input.is_empty() {
            return Err("trailing live current packet");
        }
        Ok(Self { metadata, packet })
    }
}

#[derive(Clone)]
pub struct CurrentViewQuery {
    pub workspace: [u8; 32],
    pub authority: [u8; 32],
    pub epoch: u64,
    pub policy_revision: u64,
    pub topic: Topic,
    pub selector: [u8; 32],
}

impl CurrentViewQuery {
    fn context(&self) -> Vec<u8> {
        let mut bytes = b"data-fabric/current-view/v1\0".to_vec();
        bytes.extend(self.workspace);
        bytes.extend(self.authority);
        bytes.extend(self.epoch.to_be_bytes());
        bytes.extend(self.policy_revision.to_be_bytes());
        bytes.push(self.topic.as_str().len() as u8);
        bytes.extend(self.topic.as_str().as_bytes());
        bytes.extend(self.selector);
        bytes
    }

    pub fn to_wire(&self) -> Result<Vec<u8>, &'static str> {
        let mut bytes = QUERY.to_vec();
        bytes.extend(self.workspace);
        bytes.extend(self.authority);
        bytes.extend(self.epoch.to_be_bytes());
        bytes.extend(self.policy_revision.to_be_bytes());
        bytes.push(self.topic.as_str().len() as u8);
        bytes.extend(self.topic.as_str().as_bytes());
        bytes.extend(self.selector);
        if bytes.len() > super::wire::MAX_QUERY_BYTES {
            return Err("current-view query exceeds bound");
        }
        Ok(bytes)
    }

    pub fn from_wire(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() > super::wire::MAX_QUERY_BYTES {
            return Err("current-view query exceeds bound");
        }
        let mut input = bytes;
        if take(&mut input, 5)? != QUERY {
            return Err("wrong current-view query format");
        }
        let query = Self {
            workspace: take(&mut input, 32)?.try_into().unwrap(),
            authority: take(&mut input, 32)?.try_into().unwrap(),
            epoch: number64(&mut input)?,
            policy_revision: number64(&mut input)?,
            topic: read_topic(&mut input)?,
            selector: take(&mut input, 32)?.try_into().unwrap(),
        };
        if !input.is_empty() {
            return Err("trailing current-view query");
        }
        Ok(query)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CurrentValue {
    pub replacement_key: [u8; 32],
    pub expires_at: u64,
    pub tombstone: bool,
    pub packet: Vec<u8>,
}

#[derive(Clone)]
pub struct CurrentView {
    pub manifest: Vec<u8>,
    pub packets: Vec<Vec<u8>>,
}

impl CurrentView {
    pub fn to_wire(&self) -> Result<Vec<u8>, &'static str> {
        if self.packets.len() > MAX_CURRENT_VALUES
            || self.manifest.is_empty()
            || self.manifest.len() > MAX_APPLICATION_CIPHERTEXT
        {
            return Err("current-view reply exceeds bounds");
        }
        let mut bytes = REPLY.to_vec();
        bytes.push(0);
        bytes.extend((self.manifest.len() as u32).to_be_bytes());
        bytes.extend(&self.manifest);
        bytes.push(self.packets.len() as u8);
        for packet in &self.packets {
            bytes.extend((packet.len() as u32).to_be_bytes());
            bytes.extend(packet);
        }
        if bytes.len() > super::wire::MAX_REPLY_BYTES {
            return Err("current-view reply exceeds bounds");
        }
        Ok(bytes)
    }

    pub fn from_wire(bytes: &[u8]) -> Result<Option<Self>, &'static str> {
        if bytes.len() > super::wire::MAX_REPLY_BYTES {
            return Err("current-view reply exceeds bounds");
        }
        let mut input = bytes;
        if take(&mut input, 5)? != REPLY {
            return Err("wrong current-view reply format");
        }
        match take(&mut input, 1)?[0] {
            1 if input.is_empty() => return Ok(None),
            0 => {}
            _ => return Err("invalid current-view reply status"),
        }
        let manifest_length = number32(&mut input)?;
        if manifest_length == 0 || manifest_length > MAX_APPLICATION_CIPHERTEXT {
            return Err("invalid current-view manifest length");
        }
        let manifest = take(&mut input, manifest_length)?.to_vec();
        let count = take(&mut input, 1)?[0] as usize;
        if count > MAX_CURRENT_VALUES {
            return Err("current-view reply exceeds bounds");
        }
        let mut packets = Vec::with_capacity(count);
        for _ in 0..count {
            let length = number32(&mut input)?;
            if !(22..=16 * 1024).contains(&length) {
                return Err("invalid current-view packet length");
            }
            packets.push(take(&mut input, length)?.to_vec());
        }
        if !input.is_empty() {
            return Err("trailing current-view reply");
        }
        Ok(Some(Self { manifest, packets }))
    }

    pub fn denied_wire() -> Vec<u8> {
        [REPLY, &[1]].concat()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct VerifiedCurrentView {
    pub cut: u64,
    pub values: Vec<CurrentValue>,
}

impl VerifiedCurrentView {
    pub fn current_values(&self, now: u64) -> impl Iterator<Item = &CurrentValue> {
        self.values
            .iter()
            .filter(move |value| value.expires_at > now)
    }
}

#[derive(Clone)]
struct IndexedValue {
    context: PublicationContext,
    selector: [u8; 32],
    value: CurrentValue,
}

#[derive(Clone)]
pub struct CurrentViewIndex {
    workspace: [u8; 32],
    authority: [u8; 32],
    epoch: u64,
    cuts: BTreeMap<(u64, Topic, [u8; 32]), u64>,
    values: BTreeMap<(u64, Topic, [u8; 32], [u8; 32]), IndexedValue>,
}

impl CurrentViewIndex {
    pub fn new(workspace: [u8; 32], authority: [u8; 32], epoch: u64) -> Self {
        Self {
            workspace,
            authority,
            epoch,
            cuts: BTreeMap::new(),
            values: BTreeMap::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.values.len()
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    pub fn retained_bytes(&self) -> usize {
        self.values
            .values()
            .map(|entry| entry.value.packet.len())
            .sum()
    }

    /// Caller stores these bytes inside the authenticated workspace record.
    pub fn snapshot(&self) -> Result<Vec<u8>, &'static str> {
        self.validate()?;
        let mut bytes = TOMBSTONE_INDEX.to_vec();
        bytes.extend(self.workspace);
        bytes.extend(self.authority);
        bytes.extend(self.epoch.to_be_bytes());
        bytes.push(self.cuts.len() as u8);
        for ((revision, topic, selector), cut) in &self.cuts {
            bytes.extend(revision.to_be_bytes());
            bytes.push(topic.as_str().len() as u8);
            bytes.extend(topic.as_str().as_bytes());
            bytes.extend(selector);
            bytes.extend(cut.to_be_bytes());
        }
        bytes.push(self.values.len() as u8);
        for ((revision, topic, selector, replacement_key), entry) in &self.values {
            bytes.extend(revision.to_be_bytes());
            bytes.push(topic.as_str().len() as u8);
            bytes.extend(topic.as_str().as_bytes());
            bytes.extend(selector);
            bytes.extend(replacement_key);
            bytes.extend(entry.value.expires_at.to_be_bytes());
            bytes.push(entry.value.tombstone.into());
            bytes.extend((entry.value.packet.len() as u32).to_be_bytes());
            bytes.extend(&entry.value.packet);
        }
        if bytes.len() > super::wire::MAX_REPLY_BYTES {
            return Err("current-view snapshot exceeds bound");
        }
        Ok(bytes)
    }

    pub fn restore(
        workspace: [u8; 32],
        authority: [u8; 32],
        epoch: u64,
        bytes: &[u8],
    ) -> Result<Self, &'static str> {
        if bytes.len() > super::wire::MAX_REPLY_BYTES {
            return Err("current-view snapshot exceeds bound");
        }
        let mut input = bytes;
        let format = take(&mut input, 5)?;
        if (format != INDEX && format != TOMBSTONE_INDEX)
            || take(&mut input, 32)? != workspace
            || take(&mut input, 32)? != authority
            || number64(&mut input)? != epoch
        {
            return Err("current-view snapshot has wrong owner");
        }
        let cut_count = take(&mut input, 1)?[0] as usize;
        if cut_count > MAX_CURRENT_SELECTIONS {
            return Err("current-view selection capacity exceeded");
        }
        let mut cuts = BTreeMap::new();
        let mut previous_cut = None;
        for _ in 0..cut_count {
            let revision = number64(&mut input)?;
            let topic = read_topic(&mut input)?;
            let selector = take(&mut input, 32)?.try_into().unwrap();
            let cut = number64(&mut input)?;
            let key = (revision, topic, selector);
            if cut == 0
                || previous_cut
                    .as_ref()
                    .is_some_and(|previous| previous >= &key)
                || cuts.insert(key.clone(), cut).is_some()
            {
                return Err("invalid current-view cut");
            }
            previous_cut = Some(key);
        }
        let value_count = take(&mut input, 1)?[0] as usize;
        if value_count > MAX_CURRENT_VALUES {
            return Err("current-view value capacity exhausted");
        }
        let mut values = BTreeMap::new();
        let mut previous_value = None;
        for _ in 0..value_count {
            let revision = number64(&mut input)?;
            let topic = read_topic(&mut input)?;
            let selector = take(&mut input, 32)?.try_into().unwrap();
            let replacement_key = take(&mut input, 32)?.try_into().unwrap();
            let expires_at = number64(&mut input)?;
            let tombstone = if format == TOMBSTONE_INDEX {
                match take(&mut input, 1)?[0] {
                    0 => false,
                    1 => true,
                    _ => return Err("invalid current tombstone"),
                }
            } else {
                false
            };
            let length = number32(&mut input)?;
            let packet = take(&mut input, length)?.to_vec();
            let (context, _) =
                PublicationContext::unpack(workspace, revision, topic.clone(), &packet)?;
            let key = (revision, topic, selector, replacement_key);
            if previous_value
                .as_ref()
                .is_some_and(|previous| previous >= &key)
                || values
                    .insert(
                        key.clone(),
                        IndexedValue {
                            context,
                            selector,
                            value: CurrentValue {
                                replacement_key,
                                expires_at,
                                tombstone,
                                packet,
                            },
                        },
                    )
                    .is_some()
            {
                return Err("duplicate current value");
            }
            previous_value = Some(key);
        }
        if !input.is_empty() {
            return Err("trailing current-view snapshot");
        }
        let index = Self {
            workspace,
            authority,
            epoch,
            cuts,
            values,
        };
        index.validate()?;
        Ok(index)
    }

    pub fn insert(
        &mut self,
        context: PublicationContext,
        selector: [u8; 32],
        replacement_key: [u8; 32],
        expires_at: u64,
        tombstone: bool,
        packet: Vec<u8>,
    ) -> Result<(), &'static str> {
        let sequence = context
            .sequence
            .ok_or("current value lacks publisher sequence")?
            .get();
        let (unpacked, _) = PublicationContext::unpack(
            context.workspace,
            context.revision,
            context.topic.clone(),
            &packet,
        )?;
        if context != unpacked || context.workspace != self.workspace || expires_at == 0 {
            return Err("invalid current value");
        }
        let key = (
            context.revision,
            context.topic.clone(),
            selector,
            replacement_key,
        );
        if let Some(existing) = self.values.get(&key) {
            let current = existing.context.sequence.unwrap().get();
            if sequence < current {
                return Ok(());
            }
            if sequence == current {
                return if existing.context == context
                    && existing.value.expires_at == expires_at
                    && existing.value.tombstone == tombstone
                    && existing.value.packet == packet
                {
                    Ok(())
                } else {
                    Err("conflicting current value")
                };
            }
        } else if self.values.len() == MAX_CURRENT_VALUES {
            return Err("current-view value capacity exhausted");
        }
        if self
            .values
            .iter()
            .any(|(stored_key, entry)| stored_key != &key && entry.context.id == context.id)
        {
            return Err("publication identity already indexes another current value");
        }
        let prior = self
            .values
            .get(&key)
            .map_or(0, |entry| entry.value.packet.len());
        if self
            .retained_bytes()
            .checked_sub(prior)
            .and_then(|bytes| bytes.checked_add(packet.len()))
            .is_none_or(|bytes| bytes > MAX_PACKET_BYTES)
        {
            return Err("current-view byte capacity exhausted");
        }
        let scope = (context.revision, context.topic.clone(), selector);
        if !self.cuts.contains_key(&scope) && self.cuts.len() == MAX_CURRENT_SELECTIONS {
            return Err("current-view selection capacity exhausted");
        }
        let cut = self
            .cuts
            .get(&scope)
            .copied()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or("current-view cut exhausted")?;
        self.values.insert(
            key,
            IndexedValue {
                context,
                selector,
                value: CurrentValue {
                    replacement_key,
                    expires_at,
                    tombstone,
                    packet,
                },
            },
        );
        self.cuts.insert(scope, cut);
        Ok(())
    }

    pub fn view(
        &self,
        owner: &Workspace,
        query: &CurrentViewQuery,
    ) -> Result<CurrentView, &'static str> {
        if query.workspace != self.workspace
            || query.authority != self.authority
            || query.epoch != self.epoch
        {
            return Err("current-view query does not match index");
        }
        let values = self
            .values
            .values()
            .filter(|entry| {
                entry.context.revision == query.policy_revision
                    && entry.context.topic == query.topic
                    && entry.selector == query.selector
            })
            .map(|entry| entry.value.clone())
            .collect::<Vec<_>>();
        let cut = self
            .cuts
            .get(&(query.policy_revision, query.topic.clone(), query.selector))
            .copied()
            .unwrap_or(0);
        protect(owner, query, cut, &values)
    }

    /// Serve through an authenticated transport peer after rechecking current
    /// membership and topic policy. A denial reveals neither values nor emptiness.
    pub fn serve(
        &self,
        owner: &Workspace,
        policy: &arachne_routing::RoutingTable,
        requester: [u8; 32],
        query: &CurrentViewQuery,
    ) -> Result<Vec<u8>, &'static str> {
        let topics = BTreeSet::from([query.topic.clone()]);
        if query.workspace != self.workspace
            || query.authority != self.authority
            || query.epoch != self.epoch
            || super::authorize_history(
                owner,
                policy,
                requester,
                query.authority,
                query.policy_revision,
                &topics,
            )
            .is_err()
        {
            return Ok(CurrentView::denied_wire());
        }
        self.view(owner, query)?.to_wire()
    }

    fn validate(&self) -> Result<(), &'static str> {
        if self.cuts.len() > MAX_CURRENT_SELECTIONS
            || self.values.len() > MAX_CURRENT_VALUES
            || self.cuts.values().any(|cut| *cut == 0)
            || bounded_packet_bytes(
                self.values.len(),
                self.values
                    .values()
                    .map(|entry| entry.value.packet.as_slice()),
            )
            .is_none()
        {
            return Err("invalid current-view index bounds");
        }
        let mut ids = BTreeSet::new();
        for ((revision, topic, selector, replacement_key), entry) in &self.values {
            let (context, _) = PublicationContext::unpack(
                self.workspace,
                entry.context.revision,
                topic.clone(),
                &entry.value.packet,
            )?;
            if context != entry.context
                || entry.context.sequence.is_none()
                || entry.context.revision != *revision
                || entry.selector != *selector
                || entry.value.replacement_key != *replacement_key
                || entry.value.expires_at == 0
                || !ids.insert(entry.context.id)
                || !self
                    .cuts
                    .contains_key(&(entry.context.revision, topic.clone(), *selector))
            {
                return Err("invalid current-view index");
            }
        }
        Ok(())
    }
}

pub fn protect(
    owner: &Workspace,
    query: &CurrentViewQuery,
    cut: u64,
    values: &[CurrentValue],
) -> Result<CurrentView, &'static str> {
    if owner.id() != query.workspace
        || owner.epoch() != query.epoch
        || owner.member().map(|member| member.id()) != Some(query.authority)
    {
        return Err("current-view authority does not match owner");
    }
    let entries = entries(query, cut, values)?;
    let manifest = owner.sign_current_view(&query.context(), &entries)?;
    Ok(CurrentView {
        manifest,
        packets: values.iter().map(|value| value.packet.clone()).collect(),
    })
}

pub fn verify(
    owner: &Workspace,
    query: &CurrentViewQuery,
    view: &CurrentView,
) -> Result<VerifiedCurrentView, &'static str> {
    if owner.id() != query.workspace || owner.epoch() != query.epoch {
        return Err("current-view scope is not current");
    }
    let packet_bytes =
        bounded_packet_bytes(view.packets.len(), view.packets.iter().map(Vec::as_slice))
            .ok_or("current-view packets exceed bounds")?;
    if view
        .manifest
        .len()
        .checked_add(packet_bytes)
        .is_none_or(|total| total > super::wire::MAX_REPLY_BYTES)
    {
        return Err("current-view packets exceed bounds");
    }
    let authenticated =
        owner.verify_current_view(query.authority, &query.context(), &view.manifest)?;
    let (cut, metadata) = parse(authenticated)?;
    if metadata.len() != view.packets.len() {
        return Err("current-view packet count mismatch");
    }
    let values = metadata
        .into_iter()
        .zip(&view.packets)
        .map(
            |((replacement_key, expires_at, tombstone, expected), packet)| {
                if Sha256::digest(packet).as_slice() != expected {
                    return Err("current-view packet digest mismatch");
                }
                Ok(CurrentValue {
                    replacement_key,
                    expires_at,
                    tombstone,
                    packet: packet.clone(),
                })
            },
        )
        .collect::<Result<Vec<_>, _>>()?;
    if entries(query, cut, &values)? != authenticated {
        return Err("current-view manifest does not match packets");
    }
    Ok(VerifiedCurrentView { cut, values })
}

/// A denial is advisory and cannot establish an empty/current selection.
pub fn verify_wire_reply(
    owner: &Workspace,
    query: &CurrentViewQuery,
    bytes: &[u8],
) -> Result<Option<VerifiedCurrentView>, &'static str> {
    CurrentView::from_wire(bytes)?
        .map(|view| verify(owner, query, &view))
        .transpose()
}

fn entries(
    query: &CurrentViewQuery,
    cut: u64,
    values: &[CurrentValue],
) -> Result<Vec<u8>, &'static str> {
    if values.len() > MAX_CURRENT_VALUES
        || values
            .windows(2)
            .any(|pair| pair[0].replacement_key >= pair[1].replacement_key)
        || bounded_packet_bytes(
            values.len(),
            values.iter().map(|value| value.packet.as_slice()),
        )
        .is_none()
    {
        return Err("current-view values exceed bounds or are not canonical");
    }
    let mut ids = BTreeSet::new();
    let tombstones = values.iter().any(|value| value.tombstone);
    let mut bytes = if tombstones {
        TOMBSTONE_MANIFEST.to_vec()
    } else {
        MANIFEST.to_vec()
    };
    bytes.extend(cut.to_be_bytes());
    bytes.extend((values.len() as u16).to_be_bytes());
    for value in values {
        let (context, _) = PublicationContext::unpack(
            query.workspace,
            query.policy_revision,
            query.topic.clone(),
            &value.packet,
        )?;
        let sequence = context
            .sequence
            .ok_or("current value lacks publisher sequence")?;
        if value.expires_at == 0 || !ids.insert(context.id) {
            return Err("invalid current value");
        }
        bytes.extend(value.replacement_key);
        bytes.extend(context.id);
        bytes.extend(sequence.get().to_be_bytes());
        bytes.extend(value.expires_at.to_be_bytes());
        if tombstones {
            bytes.push(value.tombstone.into());
        }
        bytes.extend(Sha256::digest(&value.packet));
    }
    Ok(bytes)
}

fn bounded_packet_bytes<'a>(
    count: usize,
    mut packets: impl Iterator<Item = &'a [u8]>,
) -> Option<usize> {
    (count <= MAX_CURRENT_VALUES)
        .then(|| packets.try_fold(0usize, |total, packet| total.checked_add(packet.len())))
        .flatten()
        .filter(|total| *total <= MAX_PACKET_BYTES)
}

type Entry = ([u8; 32], u64, bool, [u8; 32]);

fn parse(mut bytes: &[u8]) -> Result<(u64, Vec<Entry>), &'static str> {
    if bytes.len() < 15 || (!bytes.starts_with(MANIFEST) && !bytes.starts_with(TOMBSTONE_MANIFEST))
    {
        return Err("invalid current-view manifest");
    }
    let tombstones = bytes.starts_with(TOMBSTONE_MANIFEST);
    bytes = &bytes[5..];
    let cut = u64::from_be_bytes(bytes[..8].try_into().unwrap());
    let count = u16::from_be_bytes(bytes[8..10].try_into().unwrap()) as usize;
    bytes = &bytes[10..];
    let entry_bytes = if tombstones {
        TOMBSTONE_ENTRY_BYTES
    } else {
        ENTRY_BYTES
    };
    if count > MAX_CURRENT_VALUES || bytes.len() != count * entry_bytes {
        return Err("invalid current-view manifest size");
    }
    let entries = bytes
        .chunks(entry_bytes)
        .map(|entry| {
            let tombstone = if tombstones {
                match entry[64] {
                    0 => false,
                    1 => true,
                    _ => return Err("invalid current tombstone"),
                }
            } else {
                false
            };
            Ok((
                entry[..32].try_into().unwrap(),
                u64::from_be_bytes(entry[56..64].try_into().unwrap()),
                tombstone,
                entry[entry_bytes - 32..entry_bytes].try_into().unwrap(),
            ))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok((cut, entries))
}

fn take<'a>(bytes: &mut &'a [u8], count: usize) -> Result<&'a [u8], &'static str> {
    let (head, tail) = bytes
        .split_at_checked(count)
        .ok_or("truncated current-view snapshot")?;
    *bytes = tail;
    Ok(head)
}

fn number64(bytes: &mut &[u8]) -> Result<u64, &'static str> {
    Ok(u64::from_be_bytes(take(bytes, 8)?.try_into().unwrap()))
}

fn number32(bytes: &mut &[u8]) -> Result<usize, &'static str> {
    Ok(u32::from_be_bytes(take(bytes, 4)?.try_into().unwrap()) as usize)
}

fn read_topic(bytes: &mut &[u8]) -> Result<Topic, &'static str> {
    let length = take(bytes, 1)?[0] as usize;
    let value =
        std::str::from_utf8(take(bytes, length)?).map_err(|_| "invalid current-view topic")?;
    Topic::new(value).map_err(|_| "invalid current-view topic")
}

#[cfg(test)]
mod tests {
    use super::*;
    use arachne_routing::{Permissions, RoutingTable};
    use arachne_security::PendingJoin;
    use std::num::NonZeroU64;

    fn pair() -> (Workspace, Workspace) {
        let admin = Workspace::create([1; 32], "Publisher").unwrap();
        let (invite, checkpoint) = admin.issue_invitation().unwrap();
        let pending =
            PendingJoin::from_invitation(&invite, &checkpoint, [2; 32], "Reader").unwrap();
        let prepared = admin
            .prepare_admission([2; 32], pending.admission_request().unwrap())
            .unwrap();
        let mut proof = pending.join_proof().unwrap();
        proof
            .apply_add(&prepared.authorization, &prepared.commit)
            .unwrap();
        let reader = pending
            .prepare_workspace(&proof, &prepared.welcome)
            .unwrap();
        (prepared.workspace, reader)
    }

    #[test]
    fn exact_authenticated_view_allows_empty_and_rejects_substitution() {
        let (mut publisher, reader) = pair();
        let topic = Topic::new("streams/opaque").unwrap();
        let query = CurrentViewQuery {
            workspace: publisher.id(),
            authority: publisher.member().unwrap().id(),
            epoch: publisher.epoch(),
            policy_revision: 7,
            topic: topic.clone(),
            selector: [8; 32],
        };
        let value = |publisher: &mut Workspace, key, id, sequence, payload: &[u8]| {
            let context = PublicationContext {
                workspace: publisher.id(),
                revision: 7,
                topic: topic.clone(),
                id: [id; 16],
                sequence: NonZeroU64::new(sequence),
            };
            let ciphertext = publisher
                .protect_application(&context.authenticated_bytes(), payload)
                .unwrap();
            CurrentValue {
                replacement_key: [key; 32],
                expires_at: 100,
                tombstone: false,
                packet: context.packet(&ciphertext).unwrap(),
            }
        };
        let values = vec![
            value(&mut publisher, 1, 1, 1, b"first"),
            value(&mut publisher, 2, 2, 2, b"second"),
        ];
        let metadata = CurrentMetadata {
            selector: query.selector,
            replacement_key: values[0].replacement_key,
            expires_at: values[0].expires_at,
            tombstone: false,
        };
        let live = LiveCurrentPacket {
            metadata,
            packet: values[0].packet.clone(),
        };
        let encoded_live = live.to_wire().unwrap();
        assert_eq!(LiveCurrentPacket::from_wire(&encoded_live).unwrap(), live);
        assert!(LiveCurrentPacket::from_wire(&encoded_live[..encoded_live.len() - 1]).is_err());
        let (live_context, _) =
            PublicationContext::unpack(query.workspace, 7, topic.clone(), &live.packet).unwrap();
        let mut altered = metadata;
        altered.expires_at += 1;
        assert_ne!(
            metadata.authenticated_context(&live_context),
            altered.authenticated_context(&live_context)
        );
        altered = metadata;
        altered.tombstone = true;
        let tombstone = LiveCurrentPacket {
            metadata: altered,
            packet: values[0].packet.clone(),
        };
        assert_eq!(
            LiveCurrentPacket::from_wire(&tombstone.to_wire().unwrap()).unwrap(),
            tombstone
        );
        assert_ne!(
            metadata.authenticated_context(&live_context),
            altered.authenticated_context(&live_context)
        );
        let view = protect(&publisher, &query, 2, &values).unwrap();
        let verified = verify(&reader, &query, &view).unwrap();
        assert_eq!(verified.cut, 2);
        assert_eq!(verified.values, values);

        let encoded_query = query.to_wire().unwrap();
        let decoded_query = CurrentViewQuery::from_wire(&encoded_query).unwrap();
        assert_eq!(decoded_query.workspace, query.workspace);
        assert_eq!(decoded_query.authority, query.authority);
        assert_eq!(decoded_query.epoch, query.epoch);
        assert_eq!(decoded_query.policy_revision, query.policy_revision);
        assert_eq!(decoded_query.topic, query.topic);
        assert_eq!(decoded_query.selector, query.selector);
        assert!(CurrentViewQuery::from_wire(&encoded_query[..encoded_query.len() - 1]).is_err());

        let encoded_view = view.to_wire().unwrap();
        assert_eq!(
            verify_wire_reply(&reader, &query, &encoded_view).unwrap(),
            Some(VerifiedCurrentView {
                cut: 2,
                values: values.clone(),
            })
        );
        assert_eq!(
            verify_wire_reply(&reader, &query, &CurrentView::denied_wire()).unwrap(),
            None
        );
        assert!(
            verify_wire_reply(&reader, &query, &encoded_view[..encoded_view.len() - 1]).is_err()
        );

        let mut wrong = query.clone();
        wrong.selector[0] ^= 1;
        assert!(verify(&reader, &wrong, &view).is_err());
        let mut damaged = view.clone();
        damaged.packets[0][0] ^= 1;
        assert_eq!(
            verify(&reader, &query, &damaged).unwrap_err(),
            "current-view packet digest mismatch"
        );
        let mut forged = view.clone();
        let last = forged.manifest.len() - 1;
        forged.manifest[last] ^= 1;
        assert!(verify(&reader, &query, &forged).is_err());
        let mut reversed = values.clone();
        reversed.reverse();
        assert!(protect(&publisher, &query, 2, &reversed).is_err());

        let empty = protect(&publisher, &query, 2, &[]).unwrap();
        assert!(verify(&reader, &query, &empty).unwrap().values.is_empty());
    }

    #[test]
    fn latest_value_index_coalesces_isolates_and_expires() {
        let (mut publisher, reader) = pair();
        let topic = Topic::new("streams/opaque").unwrap();
        let authority = publisher.member().unwrap().id();
        let query = CurrentViewQuery {
            workspace: publisher.id(),
            authority,
            epoch: publisher.epoch(),
            policy_revision: 7,
            topic: topic.clone(),
            selector: [8; 32],
        };
        let packet = |publisher: &mut Workspace, id, sequence, payload: &[u8]| {
            let context = PublicationContext {
                workspace: publisher.id(),
                revision: 7,
                topic: topic.clone(),
                id: [id; 16],
                sequence: NonZeroU64::new(sequence),
            };
            let ciphertext = publisher
                .protect_application(&context.authenticated_bytes(), payload)
                .unwrap();
            let packet = context.packet(&ciphertext).unwrap();
            (context, packet)
        };
        let mut index = CurrentViewIndex::new(publisher.id(), authority, publisher.epoch());
        let (first, first_packet) = packet(&mut publisher, 1, 1, b"old");
        index
            .insert(first, [8; 32], [1; 32], 20, false, first_packet)
            .unwrap();
        let (other, other_packet) = packet(&mut publisher, 2, 2, b"other selector");
        index
            .insert(other, [9; 32], [2; 32], 30, false, other_packet)
            .unwrap();
        let (newer, newer_packet) = packet(&mut publisher, 3, 3, b"new");
        index
            .insert(
                newer.clone(),
                [8; 32],
                [1; 32],
                30,
                false,
                newer_packet.clone(),
            )
            .unwrap();
        index
            .insert(newer, [8; 32], [1; 32], 30, false, newer_packet)
            .unwrap();
        let revision_eight = PublicationContext {
            workspace: publisher.id(),
            revision: 8,
            topic: topic.clone(),
            id: [4; 16],
            sequence: NonZeroU64::new(1),
        };
        let revision_eight_object = publisher
            .protect_application(&revision_eight.authenticated_bytes(), b"new policy")
            .unwrap();
        index
            .insert(
                revision_eight.clone(),
                [8; 32],
                [1; 32],
                40,
                false,
                revision_eight.packet(&revision_eight_object).unwrap(),
            )
            .unwrap();
        assert_eq!(index.len(), 3);

        let view = index.view(&publisher, &query).unwrap();
        let current = verify(&reader, &query, &view).unwrap();
        assert_eq!(current.cut, 2);
        assert_eq!(current.values.len(), 1);
        assert_eq!(current.values[0].replacement_key, [1; 32]);
        assert_eq!(current.current_values(30).count(), 0);

        let mut revision_eight_query = query.clone();
        revision_eight_query.policy_revision = 8;
        let revision_eight_view = verify(
            &reader,
            &revision_eight_query,
            &index.view(&publisher, &revision_eight_query).unwrap(),
        )
        .unwrap();
        assert_eq!(revision_eight_view.cut, 1);
        assert_eq!(revision_eight_view.values[0].expires_at, 40);

        let mut other_query = query.clone();
        other_query.selector = [9; 32];
        let other = verify(
            &reader,
            &other_query,
            &index.view(&publisher, &other_query).unwrap(),
        )
        .unwrap();
        assert_eq!(other.cut, 1);
        assert_eq!(other.values[0].replacement_key, [2; 32]);

        let mut policy = RoutingTable::default();
        policy
            .install_verified_policy(
                publisher.id(),
                7,
                BTreeMap::from([
                    ([1; 32], Permissions::AllTopics),
                    ([2; 32], Permissions::AllTopics),
                ]),
            )
            .unwrap();
        let served = index.serve(&publisher, &policy, [2; 32], &query).unwrap();
        assert_eq!(
            verify_wire_reply(&reader, &query, &served)
                .unwrap()
                .unwrap()
                .cut,
            2
        );
        assert_eq!(
            index.serve(&publisher, &policy, [3; 32], &query).unwrap(),
            CurrentView::denied_wire()
        );

        let saved = index.snapshot().unwrap();
        let restored =
            CurrentViewIndex::restore(publisher.id(), authority, publisher.epoch(), &saved)
                .unwrap();
        assert_eq!(restored.snapshot().unwrap(), saved);
        let restored_view = restored.view(&publisher, &query).unwrap();
        let restored_current = verify(&reader, &query, &restored_view).unwrap();
        assert_eq!(restored_current.cut, 2);
        assert_eq!(restored_current.values[0].replacement_key, [1; 32]);
        assert!(CurrentViewIndex::restore([0; 32], authority, publisher.epoch(), &saved).is_err());
        let mut trailing = saved;
        trailing.push(0);
        assert!(
            CurrentViewIndex::restore(publisher.id(), authority, publisher.epoch(), &trailing)
                .is_err()
        );
    }
}
