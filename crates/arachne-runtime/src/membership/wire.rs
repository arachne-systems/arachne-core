//! Version-1 state comparison. JSON remains the native client interface, not
//! the representation of repeated peer metadata. Signed records stay opaque.
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const QUERY: &[u8] = b"DFMQ\x01";
const REPLY: &[u8] = b"DFMR\x01";
const MAX_QUERY: usize = 256 + 2 * arachne_security::MAX_MEMBER_PROFILE;
const RANGE_QUERY: &[u8] = b"DFMS\x01";
const RANGE_REPLY: &[u8] = b"DFMT\x01";
const MAX_RANGE_QUERY: usize = 64;
/// Steps in one range reply. Matches the held-step bound, so a whole reply
/// always fits where steps wait for their turn (ADR 0009).
pub(super) const MAX_RANGE_STEPS: usize = 32;

const PROFILE_QUERY: &[u8] = b"DFPQ\x01";
const PROFILE_PAGE: &[u8] = b"DFPS\x01";
const MAX_PROFILE_QUERY: usize = 80;
/// Signed profiles in one page: at most 12.5 KB at the longest names.
pub(crate) const MAX_PAGE_PROFILES: usize = 32;

/// Ask a peer for its retained signed profiles after one member id, in id
/// order. `None` starts at the first.
#[derive(Serialize, Deserialize)]
pub(crate) struct ProfileQuery {
    pub workspace: [u8; 32],
    pub after: Option<[u8; 32]>,
}

/// Up to `MAX_PAGE_PROFILES` signed profiles, in member-id order. Each is
/// only a claim until the receiver verifies it against its own roster.
#[derive(Serialize, Deserialize)]
pub(crate) struct ProfilePage<'a> {
    pub workspace: [u8; 32],
    #[serde(borrow)]
    pub profiles: Vec<&'a [u8]>,
}

pub(crate) fn encode_profile_query(query: &ProfileQuery) -> Result<Vec<u8>, String> {
    encode(PROFILE_QUERY, query, MAX_PROFILE_QUERY)
}

pub(crate) fn decode_profile_query(bytes: &[u8]) -> Result<ProfileQuery, String> {
    decode(PROFILE_QUERY, bytes, MAX_PROFILE_QUERY)
}

pub(crate) fn encode_profile_page(page: &ProfilePage<'_>) -> Result<Vec<u8>, String> {
    if page.profiles.len() > MAX_PAGE_PROFILES {
        return Err("too many member profiles".into());
    }
    encode(PROFILE_PAGE, page, arachne_node::MAX_CONTROL_REPLY)
}

pub(crate) fn decode_profile_page(bytes: &[u8]) -> Result<ProfilePage<'_>, String> {
    let page: ProfilePage<'_> = decode(PROFILE_PAGE, bytes, arachne_node::MAX_CONTROL_REPLY)?;
    if page.profiles.len() > MAX_PAGE_PROFILES
        || page.profiles.iter().any(|profile| {
            profile.is_empty() || profile.len() > arachne_security::MAX_MEMBER_PROFILE
        })
    {
        return Err("invalid member profile page".into());
    }
    Ok(page)
}

/// Ask a peer for the steps from `after` toward `until` in one exchange.
#[derive(Serialize, Deserialize)]
pub(super) struct RangeQuery {
    pub workspace: [u8; 32],
    pub after: u64,
    pub until: u64,
}

/// Consecutive steps from `after`, in order, each the JSON a pulled step uses.
/// Empty when the peer refuses or has nothing to give.
#[derive(Serialize, Deserialize)]
pub(super) struct RangeReply<'a> {
    pub workspace: [u8; 32],
    pub after: u64,
    #[serde(borrow)]
    pub steps: Vec<&'a [u8]>,
}

pub(super) fn encode_range_query(query: &RangeQuery) -> Result<Vec<u8>, String> {
    encode(RANGE_QUERY, query, MAX_RANGE_QUERY)
}

pub(super) fn decode_range_query(bytes: &[u8]) -> Result<RangeQuery, String> {
    decode(RANGE_QUERY, bytes, MAX_RANGE_QUERY)
}

pub(super) fn encode_range_reply(reply: &RangeReply<'_>) -> Result<Vec<u8>, String> {
    if reply.steps.len() > MAX_RANGE_STEPS {
        return Err("too many membership steps".into());
    }
    encode(RANGE_REPLY, reply, arachne_node::MAX_CONTROL_REPLY)
}

pub(super) fn decode_range_reply(bytes: &[u8]) -> Result<RangeReply<'_>, String> {
    let reply: RangeReply<'_> = decode(RANGE_REPLY, bytes, arachne_node::MAX_CONTROL_REPLY)?;
    if reply.steps.len() > MAX_RANGE_STEPS || reply.steps.iter().any(|step| step.is_empty()) {
        return Err("invalid membership range".into());
    }
    Ok(reply)
}

#[derive(Serialize, Deserialize)]
pub struct Query<'a> {
    pub workspace: [u8; 32],
    pub basis: super::StateBasis,
    pub profiles_digest: [u8; 32],
    #[serde(borrow)]
    pub profiles: [&'a [u8]; 2],
}

#[derive(Serialize, Deserialize)]
enum State {
    #[serde(rename = "membership_denied")]
    Denied,
    #[serde(rename = "membership_current")]
    Current,
    #[serde(rename = "membership_update_available")]
    UpdateAvailable,
    #[serde(rename = "membership_unavailable")]
    Unavailable,
}

#[derive(Serialize, Deserialize)]
struct Metadata {
    workspace: Option<[u8; 32]>,
    after: Option<u64>,
    epoch: Option<u64>,
    epoch_fingerprint: Option<[u8; 32]>,
    name_head: Option<[u8; 32]>,
    name_revision: Option<u64>,
    profiles_digest: Option<[u8; 32]>,
}

#[derive(Serialize, Deserialize)]
struct Reply<'a> {
    state: State,
    metadata: Metadata,
    // Fixed cardinality prevents peer-declared vector allocations. Borrow each
    // record, check its bound, then copy only for the native presentation.
    #[serde(borrow)]
    records: [&'a [u8]; 5], // step, name record, name checkpoint, own profile, retained profile
}

fn encode(prefix: &[u8], value: &impl Serialize, limit: usize) -> Result<Vec<u8>, String> {
    let mut bytes = prefix.to_vec();
    bytes.extend(postcard::to_allocvec(value).map_err(|_| "invalid membership encoding")?);
    if bytes.len() > limit {
        return Err("membership packet exceeds bound".into());
    }
    Ok(bytes)
}

fn decode<'a, T: Deserialize<'a>>(
    prefix: &[u8],
    bytes: &'a [u8],
    limit: usize,
) -> Result<T, String> {
    if bytes.len() > limit {
        return Err("membership packet exceeds bound".into());
    }
    let body = bytes
        .strip_prefix(prefix)
        .ok_or("invalid membership format")?;
    let (value, trailing) =
        postcard::take_from_bytes(body).map_err(|_| "invalid membership packet")?;
    if !trailing.is_empty() {
        return Err("trailing membership bytes".into());
    }
    Ok(value)
}

pub fn encode_query(query: &Query<'_>) -> Result<Vec<u8>, String> {
    encode(QUERY, query, MAX_QUERY)
}

pub(super) fn decode_query(bytes: &[u8]) -> Result<Query<'_>, String> {
    let query: Query<'_> = decode(QUERY, bytes, MAX_QUERY)?;
    if query
        .profiles
        .iter()
        .any(|p| p.len() > arachne_security::MAX_MEMBER_PROFILE)
    {
        return Err("member profile exceeds bound".into());
    }
    Ok(query)
}

pub(crate) fn encode_reply(value: &Value) -> Result<Vec<u8>, String> {
    let metadata =
        serde_json::from_value(value.clone()).map_err(|_| "invalid membership metadata")?;
    let state =
        serde_json::from_value(value["state"].clone()).map_err(|_| "invalid membership state")?;
    let step = value
        .get("step")
        .map(serde_json::to_vec)
        .transpose()
        .map_err(|e| e.to_string())?
        .unwrap_or_default();
    let record: Vec<u8> =
        serde_json::from_value(value.get("name_record").cloned().unwrap_or(json!([])))
            .map_err(|_| "invalid name record")?;
    let checkpoint: Vec<u8> =
        serde_json::from_value(value.get("name_checkpoint").cloned().unwrap_or(json!([])))
            .map_err(|_| "invalid name checkpoint")?;
    let profiles: Vec<Vec<u8>> =
        serde_json::from_value(value.get("profiles").cloned().unwrap_or(json!([])))
            .map_err(|_| "invalid profiles")?;
    if profiles.len() > 2 {
        return Err("too many profiles".into());
    }
    let reply = Reply {
        state,
        metadata,
        records: [
            &step,
            &record,
            &checkpoint,
            profiles.first().map_or(&[], Vec::as_slice),
            profiles.get(1).map_or(&[], Vec::as_slice),
        ],
    };
    encode(REPLY, &reply, arachne_node::MAX_CONTROL_REPLY)
}

pub fn decode_reply(bytes: &[u8]) -> Result<Value, String> {
    let reply: Reply<'_> = decode(REPLY, bytes, arachne_node::MAX_CONTROL_REPLY)?;
    let limits = [
        arachne_node::MAX_CONTROL_REPLY,
        arachne_security::MAX_WORKSPACE_NAME_RECORD,
        arachne_security::MAX_WORKSPACE_NAME_CHECKPOINT,
        arachne_security::MAX_MEMBER_PROFILE,
        arachne_security::MAX_MEMBER_PROFILE,
    ];
    if reply
        .records
        .iter()
        .zip(limits)
        .any(|(record, limit)| record.len() > limit)
    {
        return Err("membership record exceeds bound".into());
    }
    let mut value = serde_json::to_value(reply.metadata).map_err(|e| e.to_string())?;
    value.as_object_mut().unwrap().retain(|_, v| !v.is_null());
    value["state"] = serde_json::to_value(reply.state).map_err(|e| e.to_string())?;
    if !reply.records[0].is_empty() {
        value["step"] =
            serde_json::from_slice(reply.records[0]).map_err(|_| "invalid membership step")?;
    }
    for (name, bytes) in [
        ("name_record", reply.records[1]),
        ("name_checkpoint", reply.records[2]),
    ] {
        if !bytes.is_empty() {
            value[name] = json!(bytes);
        }
    }
    let profiles: Vec<_> = reply.records[3..]
        .iter()
        .filter(|p| !p.is_empty())
        .collect();
    if !profiles.is_empty() {
        value["profiles"] = json!(profiles);
    }
    Ok(value)
}

#[test]
fn compact_state_is_bounded_and_accepts_only_the_current_version_one_schema() {
    let current = json!({"state":"membership_current","workspace":([9;32]),"after":7,"epoch":7,
        "epoch_fingerprint":([10;32]),"name_head":([11;32]),"name_revision":2,"profiles_digest":([12;32])});
    let bytes = encode_reply(&current).unwrap();
    assert_eq!(decode_reply(&bytes).unwrap(), current);
    assert!(bytes.len() < 160);
    for end in 0..bytes.len() {
        assert!(decode_reply(&bytes[..end]).is_err());
    }
    let mut bad = bytes.clone();
    bad.push(0);
    assert!(decode_reply(&bad).is_err());
    bad = bytes.clone();
    bad[4] = 2;
    assert!(decode_reply(&bad).is_err());
    bad = bytes;
    bad[5] = 255;
    assert!(decode_reply(&bad).is_err());
    let query = Query {
        workspace: [9; 32],
        basis: super::StateBasis {
            epoch: 7,
            fingerprint: [10; 32],
            name_head: [11; 32],
        },
        profiles_digest: [12; 32],
        profiles: [&[], &[]],
    };
    let bytes = encode_query(&query).unwrap();
    assert!(bytes.len() < 145);
    assert_eq!(
        decode_query(&bytes).unwrap().profiles_digest,
        query.profiles_digest
    );
    let excessive = vec![0; arachne_security::MAX_MEMBER_PROFILE + 1];
    let bytes = encode_query(&Query {
        profiles: [&excessive, &[]],
        ..query
    })
    .unwrap();
    assert!(decode_query(&bytes).is_err());
}

#[test]
fn range_messages_round_trip_and_reject_oversized_or_malformed_ranges() {
    let query = RangeQuery {
        workspace: [3; 32],
        after: 7,
        until: 12,
    };
    let bytes = encode_range_query(&query).unwrap();
    let decoded = decode_range_query(&bytes).unwrap();
    assert_eq!(
        (decoded.workspace, decoded.after, decoded.until),
        ([3; 32], 7, 12)
    );
    for end in 0..bytes.len() {
        assert!(decode_range_query(&bytes[..end]).is_err());
    }
    let step = vec![b'{'; 100];
    let reply = RangeReply {
        workspace: [3; 32],
        after: 7,
        steps: vec![&step; 3],
    };
    let bytes = encode_range_reply(&reply).unwrap();
    let decoded = decode_range_reply(&bytes).unwrap();
    assert_eq!((decoded.after, decoded.steps.len()), (7, 3));
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(decode_range_reply(&trailing).is_err());
    // More steps than a member may hold, or an empty step, is refused.
    let many = RangeReply {
        workspace: [3; 32],
        after: 7,
        steps: vec![&step; MAX_RANGE_STEPS + 1],
    };
    assert!(encode_range_reply(&many).is_err());
    let mut forged = RANGE_REPLY.to_vec();
    forged.extend(postcard::to_allocvec(&many).unwrap());
    assert!(decode_range_reply(&forged).is_err());
    let empty: &[u8] = &[];
    let mut forged = RANGE_REPLY.to_vec();
    forged.extend(
        postcard::to_allocvec(&RangeReply {
            workspace: [3; 32],
            after: 7,
            steps: vec![empty],
        })
        .unwrap(),
    );
    assert!(decode_range_reply(&forged).is_err());
    // A reply over the control bound is refused on both sides.
    let big = vec![b'{'; arachne_node::MAX_CONTROL_REPLY];
    assert!(
        encode_range_reply(&RangeReply {
            workspace: [3; 32],
            after: 7,
            steps: vec![&big]
        })
        .is_err()
    );
}

#[test]
fn profile_pages_round_trip_and_reject_oversized_or_malformed_pages() {
    let query = ProfileQuery {
        workspace: [4; 32],
        after: Some([5; 32]),
    };
    let bytes = encode_profile_query(&query).unwrap();
    let decoded = decode_profile_query(&bytes).unwrap();
    assert_eq!((decoded.workspace, decoded.after), ([4; 32], Some([5; 32])));
    for end in 0..bytes.len() {
        assert!(decode_profile_query(&bytes[..end]).is_err());
    }
    let profile = vec![7; arachne_security::MAX_MEMBER_PROFILE];
    let full = ProfilePage {
        workspace: [4; 32],
        profiles: vec![&profile; MAX_PAGE_PROFILES],
    };
    let bytes = encode_profile_page(&full).unwrap();
    assert!(
        bytes.len() <= arachne_node::MAX_CONTROL_REPLY,
        "{}",
        bytes.len()
    );
    assert_eq!(
        decode_profile_page(&bytes).unwrap().profiles.len(),
        MAX_PAGE_PROFILES
    );
    let mut trailing = bytes;
    trailing.push(0);
    assert!(decode_profile_page(&trailing).is_err());
    // More profiles than a page holds, an empty or an oversized one: refused.
    let many = ProfilePage {
        workspace: [4; 32],
        profiles: vec![&profile; MAX_PAGE_PROFILES + 1],
    };
    assert!(encode_profile_page(&many).is_err());
    let oversized = vec![7; arachne_security::MAX_MEMBER_PROFILE + 1];
    let empty: &[u8] = &[];
    for bad in [
        many,
        ProfilePage {
            workspace: [4; 32],
            profiles: vec![&oversized],
        },
        ProfilePage {
            workspace: [4; 32],
            profiles: vec![empty],
        },
    ] {
        let mut forged = PROFILE_PAGE.to_vec();
        forged.extend(postcard::to_allocvec(&bad).unwrap());
        assert!(decode_profile_page(&forged).is_err());
    }
}
