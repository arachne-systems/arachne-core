//! Membership step codec, version 3 (ADR A2 section 8).
//!
//! One codec for every place a step is stored or sent: the inline join
//! history (`DFJH\x03`), the native step records (`DFWR\x03`) and the
//! standalone transport form (`DFMS\x03`). A step is:
//!
//! `kind tag (u8) || fork class (u8) || authorization fields || u32 commit length || commit`
//!
//! The class byte must equal the class of the decoded authorization, so a
//! stored tag cannot relabel a step. Older versions are rejected; there is no
//! migration (pre-release rule).
use super::{AdmissionAuthorization, ForkClass, ManagementAction, MembershipAuthorization};
use super::storage::{number, take};

/// Error for any record written by an older format.
pub const FORMAT_NOT_SUPPORTED: &str = "workspace format not supported; create the workspace again";

/// Standalone transport form of one step.
const TRANSPORT: &[u8; 5] = b"DFMS\x03";

/// Largest commit a step may carry. Management commits are capped at 64 KiB
/// by the verifier; this bound only keeps a decoder from trusting a length.
const MAX_STEP_COMMIT: usize = 1024 * 1024;

fn put_auth(out: &mut Vec<u8>, auth: &AdmissionAuthorization) {
    out.extend(auth.invitation_key);
    out.extend(auth.grant_signature);
    out.extend(auth.redemption_signature);
}

fn read_auth(bytes: &mut &[u8]) -> Result<AdmissionAuthorization, &'static str> {
    Ok(AdmissionAuthorization {
        invitation_key: take(bytes, 32)?.try_into().unwrap(),
        grant_signature: take(bytes, 64)?.try_into().unwrap(),
        redemption_signature: take(bytes, 64)?.try_into().unwrap(),
    })
}

fn array<const N: usize>(bytes: &mut &[u8]) -> Result<[u8; N], &'static str> {
    Ok(take(bytes, N)?.try_into().unwrap())
}

fn u64_be(bytes: &mut &[u8]) -> Result<u64, &'static str> {
    Ok(u64::from_be_bytes(array(bytes)?))
}

/// Kind tags of revocation steps: 2 Demote, 3 Remove, 4 Leave,
/// 6 DisableInvitation. Each carries an `OrderStep`.
fn revocation_tag(kind: super::RevocationKind) -> u8 {
    match kind {
        super::RevocationKind::Demote => 2,
        super::RevocationKind::Remove => 3,
        super::RevocationKind::Leave => 4,
        super::RevocationKind::DisableInvitation => 6,
    }
}

/// Append one step.
pub(super) fn write_step(
    out: &mut Vec<u8>,
    authorization: &MembershipAuthorization,
    commit: &[u8],
) -> Result<(), &'static str> {
    if commit.is_empty() || commit.len() > MAX_STEP_COMMIT {
        return Err("membership step commit exceeds bounds");
    }
    let class = ForkClass::of(authorization).to_u8();
    match authorization {
        MembershipAuthorization::Admission(auth) => {
            out.extend([0, class]);
            put_auth(out, auth);
        }
        MembershipAuthorization::AdmissionBatch(auths) => {
            if auths.is_empty() || auths.len() > super::MAX_ADMISSION_BATCH {
                return Err("invalid admission batch size");
            }
            out.extend([11, class]);
            out.extend((auths.len() as u16).to_be_bytes());
            for auth in auths {
                put_auth(out, auth);
            }
        }
        MembershipAuthorization::Revocation(step) => {
            out.extend([revocation_tag(step.order.kind), class]);
            super::order::write_order_step(out, step)?;
        }
        MembershipAuthorization::Management(action) => {
            let (tag, id) = match action {
                ManagementAction::Promote(id) => (1, id),
                ManagementAction::CreateInvitation(id, ..) => (5, id),
                ManagementAction::ApproveInvitation(id, _) => (7, id),
                ManagementAction::CreateAutomaticInvitation(id, ..) => (8, id),
                ManagementAction::CreateRequestInvitation(id, ..) => (9, id),
                ManagementAction::DeclineInvitationRequest(id, _) => (10, id),
                ManagementAction::Remove(_)
                | ManagementAction::Demote(_)
                | ManagementAction::DisableInvitation(_) => {
                    return Err("revocation requires a signed order");
                }
            };
            out.extend([tag, class]);
            out.extend(id);
            match action {
                ManagementAction::CreateInvitation(_, expires, personal) => {
                    out.extend(expires.to_be_bytes());
                    out.push(u8::from(*personal));
                }
                ManagementAction::CreateAutomaticInvitation(_, expires)
                | ManagementAction::CreateRequestInvitation(_, expires) => {
                    out.extend(expires.to_be_bytes())
                }
                ManagementAction::ApproveInvitation(_, package)
                | ManagementAction::DeclineInvitationRequest(_, package) => out.extend(package),
                _ => {}
            }
        }
    }
    out.extend((commit.len() as u32).to_be_bytes());
    out.extend(commit);
    Ok(())
}

/// Read one step from the front of `rest`. `rest` advances only on success.
pub(super) fn read_step(
    rest: &mut &[u8],
) -> Result<(MembershipAuthorization, Vec<u8>), &'static str> {
    let mut bytes = *rest;
    let tag = take(&mut bytes, 1)?[0];
    let class = ForkClass::from_u8(take(&mut bytes, 1)?[0])?;
    let authorization = match tag {
        0 => MembershipAuthorization::Admission(read_auth(&mut bytes)?),
        11 => {
            let count = u16::from_be_bytes(array(&mut bytes)?) as usize;
            if count == 0 || count > super::MAX_ADMISSION_BATCH {
                return Err("invalid admission batch size");
            }
            MembershipAuthorization::AdmissionBatch(
                (0..count)
                    .map(|_| read_auth(&mut bytes))
                    .collect::<Result<Vec<_>, _>>()?,
            )
        }
        2 | 3 | 4 | 6 => {
            let step = super::order::read_order_step(&mut bytes)?;
            if revocation_tag(step.order.kind) != tag {
                return Err("membership step class does not match its action");
            }
            MembershipAuthorization::Revocation(step)
        }
        1 | 5 | 7..=10 => {
            let id = array(&mut bytes)?;
            MembershipAuthorization::Management(match tag {
                1 => ManagementAction::Promote(id),
                5 => ManagementAction::CreateInvitation(
                    id,
                    u64_be(&mut bytes)?,
                    match take(&mut bytes, 1)?[0] {
                        0 => false,
                        1 => true,
                        _ => return Err("invalid invitation mode"),
                    },
                ),
                7 => ManagementAction::ApproveInvitation(id, array(&mut bytes)?),
                8 => ManagementAction::CreateAutomaticInvitation(id, u64_be(&mut bytes)?),
                9 => ManagementAction::CreateRequestInvitation(id, u64_be(&mut bytes)?),
                _ => ManagementAction::DeclineInvitationRequest(id, array(&mut bytes)?),
            })
        }
        _ => return Err("unknown membership history action"),
    };
    if ForkClass::of(&authorization) != class {
        return Err("membership step class does not match its action");
    }
    let length = number(&mut bytes)?;
    if length == 0 || length > MAX_STEP_COMMIT {
        return Err("membership step commit exceeds bounds");
    }
    let commit = take(&mut bytes, length)?.to_vec();
    *rest = bytes;
    Ok((authorization, commit))
}

/// Standalone binary form of one step, for transport between members
/// (for example history pages). Replaces the runtime's JSON step form.
pub fn encode_membership_step(
    authorization: &MembershipAuthorization,
    commit: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let mut out = TRANSPORT.to_vec();
    write_step(&mut out, authorization, commit)?;
    Ok(out)
}

/// Parse one standalone step. Structure only: the caller must still verify
/// the step, for example with `MembershipVerifier::apply_transition`.
pub fn decode_membership_step(
    bytes: &[u8],
) -> Result<(MembershipAuthorization, Vec<u8>), &'static str> {
    let mut rest = match bytes.strip_prefix(TRANSPORT) {
        Some(rest) => rest,
        None if bytes.starts_with(b"DFMS") => return Err(FORMAT_NOT_SUPPORTED),
        None => return Err("invalid membership step"),
    };
    let step = read_step(&mut rest)?;
    if !rest.is_empty() {
        return Err("invalid membership step");
    }
    Ok(step)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn admission(n: u8) -> AdmissionAuthorization {
        AdmissionAuthorization {
            invitation_key: [n; 32],
            grant_signature: [n.wrapping_add(1); 64],
            redemption_signature: [n.wrapping_add(2); 64],
        }
    }

    fn every_authorization() -> Vec<MembershipAuthorization> {
        let id = [4; 32];
        let mut all = vec![
            MembershipAuthorization::Admission(admission(1)),
            MembershipAuthorization::AdmissionBatch(vec![admission(1), admission(9)]),
        ];
        for kind in [
            crate::RevocationKind::Remove,
            crate::RevocationKind::Leave,
            crate::RevocationKind::Demote,
            crate::RevocationKind::DisableInvitation,
        ] {
            let order = crate::RevocationOrder {
                kind,
                target: id,
                issuer: [8; 32],
                anchor_epoch: 9,
                anchor_context: [10; 32],
                signature: [11; 64],
            };
            all.push(MembershipAuthorization::Revocation(crate::OrderStep::new(
                order.clone(),
            )));
            all.push(MembershipAuthorization::Revocation(
                crate::OrderStep::with_proof(
                    order,
                    crate::AnchorProof {
                        checkpoint: b"checkpoint".to_vec(),
                        winning: vec![(
                            MembershipAuthorization::Admission(admission(3)),
                            b"w".to_vec(),
                        )],
                        losing: vec![],
                    },
                ),
            ));
        }
        for action in [
            ManagementAction::Promote(id),
            ManagementAction::CreateInvitation(id, 77, true),
            ManagementAction::ApproveInvitation(id, [6; 32]),
            ManagementAction::CreateAutomaticInvitation(id, 78),
            ManagementAction::CreateRequestInvitation(id, 79),
            ManagementAction::DeclineInvitationRequest(id, [7; 32]),
        ] {
            all.push(MembershipAuthorization::Management(action));
        }
        all
    }

    fn same(a: &MembershipAuthorization, b: &MembershipAuthorization) -> bool {
        encode_membership_step(a, b"c").unwrap() == encode_membership_step(b, b"c").unwrap()
    }

    #[test]
    fn every_step_round_trips_and_carries_its_class() {
        for authorization in every_authorization() {
            let bytes = encode_membership_step(&authorization, b"commit bytes").unwrap();
            assert_eq!(&bytes[..5], b"DFMS\x03");
            assert_eq!(bytes[6], ForkClass::of(&authorization).to_u8());
            let (decoded, commit) = decode_membership_step(&bytes).unwrap();
            assert!(same(&decoded, &authorization));
            assert_eq!(commit, b"commit bytes");
            // Every truncation and any trailing byte fails.
            for length in 0..bytes.len() {
                assert!(decode_membership_step(&bytes[..length]).is_err());
            }
            let mut trailing = bytes.clone();
            trailing.push(0);
            assert!(decode_membership_step(&trailing).is_err());
        }
    }

    #[test]
    fn a_relabelled_class_or_old_version_is_rejected() {
        // A class 0/1 intent without its signed order is not representable.
        assert_eq!(
            encode_membership_step(
                &MembershipAuthorization::Management(ManagementAction::Remove([4; 32])),
                b"c"
            )
            .err(),
            Some("revocation requires a signed order")
        );
        let remove = every_authorization()
            .into_iter()
            .find(|a| a.removed_member().is_some())
            .unwrap();
        let mut bytes = encode_membership_step(&remove, b"c").unwrap();
        // Claim the Management class for a Remove.
        bytes[6] = ForkClass::Management.to_u8();
        assert_eq!(
            decode_membership_step(&bytes).err(),
            Some("membership step class does not match its action")
        );
        bytes[6] = 9;
        assert!(decode_membership_step(&bytes).is_err());
        let mut old = encode_membership_step(&remove, b"c").unwrap();
        old[4] = 2;
        assert_eq!(decode_membership_step(&old).err(), Some(FORMAT_NOT_SUPPORTED));
        let mut unknown = encode_membership_step(&remove, b"c").unwrap();
        unknown[5] = 200;
        assert!(decode_membership_step(&unknown).is_err());
        assert!(encode_membership_step(&remove, b"").is_err());
    }
}
