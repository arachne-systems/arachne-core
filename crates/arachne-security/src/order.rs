//! Revocation orders (ADR A2 section 3, step 4).
//!
//! Remove, Leave, Demote and DisableInvitation travel as signed orders. Any
//! member may commit an order; the commit sender does not need to be an
//! administrator. Validity depends only on the verifier's parent state and
//! the step itself, so every member reaches the same verdict:
//!
//! 1. The issuer signed the order.
//! 2. `parent_epoch - anchor_epoch <= ORDER_WINDOW`.
//! 3. The anchor is proven:
//!    - With no proof, the anchor must be the parent state itself
//!      (`anchor_epoch == parent` and the context hash matches).
//!    - With a proof, the verifier builds public state from the proof's
//!      checkpoint at a common ancestor C, replays the `winning` steps and
//!      requires the result to equal its own parent state (the GroupContext,
//!      with its transcript hash, binds the whole chain). It replays the
//!      `losing` steps from C to reach the anchor, which may lie on a losing
//!      branch. A remembered anchor window or local history is never used:
//!      two members with different histories would then disagree.
//! 4. The issuer was an administrator at the anchor (for Leave: the issuer
//!    is the target member's key at the anchor).
//!
//! The commit's authenticated data carries the order digest, so an order
//! cannot be attached to a commit made for another intent.
use super::storage::{number, take};
use super::{MembershipAuthorization, SUITE};
use openmls::prelude::{tls_codec::Serialize, *};
use openmls_traits::crypto::OpenMlsCrypto;
use sha2::{Digest, Sha256};

/// Epochs an order stays valid after its anchor, counted at the commit's
/// parent epoch. Validity uses the chain only, never local settlement.
pub const ORDER_WINDOW: u64 = 64;
/// Bound for one encoded anchor proof.
pub const MAX_ANCHOR_PROOF: usize = 2 * 1024 * 1024;
/// Proofs may contain order steps that carry proofs themselves. The depth is
/// bounded so verification cost is bounded and identical on every node.
pub(super) const MAX_PROOF_DEPTH: u8 = 3;

const ORDER_DOMAIN: &[u8] = b"arachne/revocation/v1";
const COMMIT_DOMAIN: &[u8] = b"arachne/revocation-commit/v1";
const ORDER_BYTES: usize = 1 + 32 + 32 + 8 + 32 + 64;

/// What a revocation order does.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum RevocationKind {
    /// Remove a member. Issued by an administrator.
    Remove = 0,
    /// A member leaves. Issued by the member itself.
    Leave = 1,
    /// Take the administrator role from a member. Issued by an administrator.
    Demote = 2,
    /// Disable an invitation (target is the invitation key). Issued by an
    /// administrator.
    DisableInvitation = 3,
}

impl RevocationKind {
    fn from_u8(value: u8) -> Result<Self, &'static str> {
        Ok(match value {
            0 => Self::Remove,
            1 => Self::Leave,
            2 => Self::Demote,
            3 => Self::DisableInvitation,
            _ => return Err("unknown revocation kind"),
        })
    }
    /// True for Remove and Leave: the target loses its keys.
    pub fn removes(self) -> bool {
        matches!(self, Self::Remove | Self::Leave)
    }
}

/// A signed intent to revoke. Fields are untrusted until verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevocationOrder {
    pub kind: RevocationKind,
    /// Member id, or the invitation key for DisableInvitation.
    pub target: [u8; 32],
    /// MLS signature key of the issuer.
    pub issuer: [u8; 32],
    pub anchor_epoch: u64,
    /// SHA-256 of the TLS-encoded public GroupContext at `anchor_epoch`.
    pub anchor_context: [u8; 32],
    pub signature: [u8; 64],
}

/// Public steps that prove an order's anchor from a common ancestor C.
#[derive(Clone)]
pub struct AnchorProof {
    /// Public checkpoint (`DFCK`) at C. Any member at C can produce one with
    /// `Workspace::public_checkpoint`. It is trusted only through `winning`.
    pub checkpoint: Vec<u8>,
    /// Steps from C to the commit's parent epoch, on the verifier's chain.
    pub winning: Vec<(MembershipAuthorization, Vec<u8>)>,
    /// Steps from C to the anchor. Empty when the anchor is C itself.
    pub losing: Vec<(MembershipAuthorization, Vec<u8>)>,
}

/// The authorization of a class 0 or class 1 step.
#[derive(Clone)]
pub struct OrderStep {
    pub order: RevocationOrder,
    pub proof: Option<AnchorProof>,
}

impl OrderStep {
    pub fn new(order: RevocationOrder) -> Self {
        Self { order, proof: None }
    }
    pub fn with_proof(order: RevocationOrder, proof: AnchorProof) -> Self {
        Self {
            order,
            proof: Some(proof),
        }
    }
}

/// SHA-256 of the TLS-encoded public GroupContext.
pub(super) fn context_hash(context: &GroupContext) -> Result<[u8; 32], &'static str> {
    Ok(Sha256::digest(
        context
            .tls_serialize_detached()
            .map_err(|_| "group context encoding failed")?,
    )
    .into())
}

impl RevocationOrder {
    fn signed_fields(&self, workspace: &[u8]) -> Vec<u8> {
        let mut bytes = ORDER_DOMAIN.to_vec();
        bytes.extend((workspace.len() as u32).to_be_bytes());
        bytes.extend(workspace);
        bytes.push(self.kind as u8);
        bytes.extend(self.target);
        bytes.extend(self.issuer);
        bytes.extend(self.anchor_epoch.to_be_bytes());
        bytes.extend(self.anchor_context);
        bytes
    }

    /// Sign a new order with `signer`, anchored at `context`.
    pub(super) fn sign(
        kind: RevocationKind,
        target: [u8; 32],
        context: &GroupContext,
        signer: &openmls_basic_credential::SignatureKeyPair,
    ) -> Result<Self, &'static str> {
        use openmls_traits::signatures::Signer;
        let mut order = Self {
            kind,
            target,
            issuer: signer
                .public()
                .try_into()
                .map_err(|_| "invalid issuer key")?,
            anchor_epoch: context.epoch().as_u64(),
            anchor_context: context_hash(context)?,
            signature: [0; 64],
        };
        order.signature = signer
            .sign(&order.signed_fields(context.group_id().as_slice()))
            .map_err(|_| "order signing failed")?
            .try_into()
            .map_err(|_| "invalid order signature length")?;
        Ok(order)
    }

    fn verify_signature(
        &self,
        crypto: &impl OpenMlsCrypto,
        workspace: &[u8],
    ) -> Result<(), &'static str> {
        crypto
            .verify_signature(
                SUITE.signature_algorithm(),
                &self.signed_fields(workspace),
                &self.issuer,
                &self.signature,
            )
            .map_err(|_| "invalid revocation order signature")
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(ORDER_BYTES);
        bytes.push(self.kind as u8);
        bytes.extend(self.target);
        bytes.extend(self.issuer);
        bytes.extend(self.anchor_epoch.to_be_bytes());
        bytes.extend(self.anchor_context);
        bytes.extend(self.signature);
        bytes
    }

    fn read(bytes: &mut &[u8]) -> Result<Self, &'static str> {
        Ok(Self {
            kind: RevocationKind::from_u8(take(bytes, 1)?[0])?,
            target: take(bytes, 32)?.try_into().unwrap(),
            issuer: take(bytes, 32)?.try_into().unwrap(),
            anchor_epoch: u64::from_be_bytes(take(bytes, 8)?.try_into().unwrap()),
            anchor_context: take(bytes, 32)?.try_into().unwrap(),
            signature: take(bytes, 64)?.try_into().unwrap(),
        })
    }

    pub fn from_bytes(mut bytes: &[u8]) -> Result<Self, &'static str> {
        let order = Self::read(&mut bytes)?;
        if !bytes.is_empty() {
            return Err("invalid revocation order");
        }
        Ok(order)
    }

    /// Digest that identifies this order, also in removal records.
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.to_bytes()).into()
    }
}

/// The authenticated data a commit for this order must carry.
pub(super) fn commit_aad(order: &RevocationOrder) -> Vec<u8> {
    let mut aad = COMMIT_DOMAIN.to_vec();
    aad.extend(order.digest());
    aad
}

pub(super) fn write_order_step(out: &mut Vec<u8>, step: &OrderStep) -> Result<(), &'static str> {
    out.extend(step.order.to_bytes());
    match &step.proof {
        None => out.push(0),
        Some(proof) => {
            out.push(1);
            let start = out.len();
            out.extend((proof.checkpoint.len() as u32).to_be_bytes());
            out.extend(&proof.checkpoint);
            for steps in [&proof.winning, &proof.losing] {
                if steps.len() > ORDER_WINDOW as usize {
                    return Err("anchor proof exceeds bounds");
                }
                out.extend((steps.len() as u16).to_be_bytes());
                for (authorization, commit) in steps {
                    super::step::write_step(out, authorization, commit)?;
                }
            }
            if out.len() - start > MAX_ANCHOR_PROOF {
                return Err("anchor proof exceeds bounds");
            }
        }
    }
    Ok(())
}

pub(super) fn read_order_step(bytes: &mut &[u8]) -> Result<OrderStep, &'static str> {
    let order = RevocationOrder::read(bytes)?;
    let proof = match take(bytes, 1)?[0] {
        0 => None,
        1 => {
            let before = bytes.len();
            let length = number(bytes)?;
            if length > MAX_ANCHOR_PROOF {
                return Err("anchor proof exceeds bounds");
            }
            let checkpoint = take(bytes, length)?.to_vec();
            let mut lists = Vec::with_capacity(2);
            for _ in 0..2 {
                let count = u16::from_be_bytes(take(bytes, 2)?.try_into().unwrap()) as usize;
                if count > ORDER_WINDOW as usize {
                    return Err("anchor proof exceeds bounds");
                }
                let mut steps = Vec::with_capacity(count);
                for _ in 0..count {
                    steps.push(super::step::read_step(bytes)?);
                }
                lists.push(steps);
            }
            if before - bytes.len() > MAX_ANCHOR_PROOF {
                return Err("anchor proof exceeds bounds");
            }
            let losing = lists.pop().unwrap();
            let winning = lists.pop().unwrap();
            Some(AnchorProof {
                checkpoint,
                winning,
                losing,
            })
        }
        _ => return Err("invalid anchor proof flag"),
    };
    Ok(OrderStep { order, proof })
}

/// Public facts at a verified anchor.
pub(super) struct Anchor {
    pub admins: Vec<Vec<u8>>,
    /// (member id, signature key) of every member at the anchor.
    pub members: Vec<([u8; 32], Vec<u8>)>,
}

fn anchor_of(group: &PublicGroup) -> Result<Anchor, &'static str> {
    Ok(Anchor {
        admins: super::bootstrap::authority(group.group_context().extensions())?,
        members: group
            .members()
            .map(|m| Ok((super::bootstrap::binding(&m.credential)?.0, m.signature_key)))
            .collect::<Result<_, &'static str>>()?,
    })
}

/// Verify an order against `parent`, the verifier's state before the commit.
/// Returns nothing on success; the caller then checks the commit itself.
pub(super) fn verify(
    parent: &super::MembershipVerifier,
    step: &OrderStep,
) -> Result<(), &'static str> {
    let order = &step.order;
    let group = &parent.group;
    let workspace: [u8; 32] = group
        .group_id()
        .as_slice()
        .try_into()
        .map_err(|_| "invalid workspace id")?;
    {
        use openmls_traits::OpenMlsProvider;
        order.verify_signature(parent.provider.crypto(), &workspace)?;
    }
    let epoch = parent.epoch();
    if epoch.saturating_sub(order.anchor_epoch) > ORDER_WINDOW {
        return Err("revocation order is outside its window");
    }
    let anchor = match &step.proof {
        None => {
            if order.anchor_epoch != epoch
                || order.anchor_context != context_hash(group.group_context())?
            {
                return Err("revocation order needs an anchor proof");
            }
            anchor_of(group)?
        }
        Some(proof) => {
            if parent.proof_depth >= MAX_PROOF_DEPTH {
                return Err("anchor proof nested too deep");
            }
            let start = |steps: &[(MembershipAuthorization, Vec<u8>)]| {
                let mut verifier = super::MembershipVerifier::from_proof_checkpoint(
                    workspace,
                    &proof.checkpoint,
                    parent.proof_depth + 1,
                )?;
                if epoch < verifier.epoch() || epoch - verifier.epoch() != proof.winning.len() as u64
                {
                    return Err("anchor proof does not reach this state");
                }
                for (authorization, commit) in steps {
                    verifier.apply_transition(authorization, commit)?;
                }
                Ok::<_, &'static str>(verifier)
            };
            // The winning replay ties C to this chain: the GroupContext
            // carries the transcript hash of every commit before it.
            let reached = start(&proof.winning)?;
            if reached.group.group_context() != group.group_context() {
                return Err("anchor proof does not reach this state");
            }
            // With no losing steps the anchor is C itself.
            let at_anchor = start(&proof.losing)?;
            if at_anchor.epoch() != order.anchor_epoch
                || context_hash(at_anchor.group.group_context())? != order.anchor_context
            {
                return Err("anchor proof does not reach the order anchor");
            }
            anchor_of(&at_anchor.group)?
        }
    };
    let issuer = order.issuer.to_vec();
    let authorized = match order.kind {
        RevocationKind::Leave => anchor
            .members
            .iter()
            .any(|(id, key)| *id == order.target && *key == issuer),
        RevocationKind::Remove | RevocationKind::Demote | RevocationKind::DisableInvitation => {
            anchor.admins.contains(&issuer)
        }
    };
    if !authorized {
        return Err(if order.kind == RevocationKind::Leave {
            "leave order is not signed by the leaving member"
        } else {
            "order issuer was not an administrator at the anchor"
        });
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        ManagementAction, PendingJoin, PreparedManagement, PreparedManagementUpdate, Workspace,
    };

    /// Apply a prepared management or revocation step as a receiver.
    pub(crate) fn follow(owner: &Workspace, change: &PreparedManagement) -> Workspace {
        match owner
            .prepare_step_update(&change.authorization, &change.commit)
            .unwrap()
        {
            PreparedManagementUpdate::Active(owner) => *owner,
            PreparedManagementUpdate::Removed(_) => panic!("receiver was removed"),
        }
    }

    /// An administrator and `count` ordinary members, all at one epoch.
    pub(crate) fn team(count: u8) -> (Workspace, Vec<Workspace>) {
        let owner = Workspace::create(crate::test_key(1), "Administrator").unwrap();
        let (registration, invite, checkpoint) = owner.prepare_invitation(0, false, false).unwrap();
        let mut admin = registration.workspace;
        let mut members: Vec<Workspace> = Vec::new();
        for n in 0..count {
            let endpoint = crate::test_endpoint(u64::from(n) + 2);
            let pending =
                PendingJoin::from_invitation(&invite, &checkpoint, crate::test_key_for(endpoint), "Member").unwrap();
            let request = pending.admission_request().unwrap();
            let admitted = admin.prepare_admission(endpoint, request).unwrap();
            let mut proof = pending.join_proof().unwrap();
            for (authorization, commit) in admitted
                .workspace
                .membership_history(endpoint, request, &checkpoint)
                .unwrap()
            {
                proof.apply_transition(&authorization, &commit).unwrap();
            }
            members = members
                .iter()
                .map(|m| {
                    m.prepare_admission_update(&admitted.authorization, &admitted.commit)
                        .unwrap()
                })
                .collect();
            members.push(pending.prepare_workspace(&proof, &admitted.welcome).unwrap());
            admin = admitted.workspace;
        }
        (admin, members)
    }

    fn id(owner: &Workspace) -> [u8; 32] {
        owner.member().unwrap().id()
    }

    fn removed(owner: &Workspace, change: &PreparedManagement) -> bool {
        matches!(
            owner
                .prepare_step_update(&change.authorization, &change.commit)
                .unwrap(),
            PreparedManagementUpdate::Removed(_)
        )
    }

    #[test]
    fn any_member_commits_an_administrator_order() {
        let (admin, members) = team(3);
        let [carrier, target, observer] = <[Workspace; 3]>::try_from(members).ok().unwrap();
        let order = admin
            .issue_revocation(RevocationKind::Remove, id(&target))
            .unwrap();
        // An ordinary member carries the administrator's order.
        let change = carrier.prepare_revocation(&OrderStep::new(order)).unwrap();
        assert!(matches!(
            change.authorization,
            MembershipAuthorization::Revocation(_)
        ));
        let admin = follow(&admin, &change);
        let observer = follow(&observer, &change);
        assert!(removed(&target, &change));
        assert_eq!(admin.member_count(), 3);
        assert_eq!(observer.epoch_fingerprint(), change.workspace.epoch_fingerprint());
        // An ordinary member cannot issue one.
        assert_eq!(
            carrier
                .issue_revocation(RevocationKind::Remove, id(&observer))
                .err(),
            Some("management actor is not an administrator")
        );
    }

    #[test]
    fn an_order_signed_by_an_ordinary_member_is_rejected_by_every_verifier() {
        let (admin, members) = team(2);
        let [forger, target] = <[Workspace; 2]>::try_from(members).ok().unwrap();
        // Sign directly, past the issuing guard.
        let forged = RevocationOrder::sign(
            RevocationKind::Remove,
            id(&target),
            forger.group.public_group().group_context(),
            &forger._signer,
        )
        .unwrap();
        assert_eq!(
            forger.prepare_revocation(&OrderStep::new(forged.clone())).err(),
            Some("order issuer was not an administrator at the anchor")
        );
        // A tampered administrator order fails its signature.
        let mut tampered = admin
            .issue_revocation(RevocationKind::Remove, id(&target))
            .unwrap();
        tampered.target = id(&forger);
        assert_eq!(
            admin.prepare_revocation(&OrderStep::new(tampered)).err(),
            Some("invalid revocation order signature")
        );
    }

    #[test]
    fn a_revocation_needs_its_order_and_the_commit_must_carry_it() {
        let (admin, members) = team(2);
        let [second, target] = <[Workspace; 2]>::try_from(members).ok().unwrap();
        let promotion = admin
            .prepare_management(ManagementAction::Promote(id(&second)))
            .unwrap();
        let second = follow(&second, &promotion);
        let target = follow(&target, &promotion);
        let admin = promotion.workspace;
        let change = admin
            .prepare_management(ManagementAction::Remove(id(&target)))
            .unwrap();
        // The intent alone does not authorize the commit.
        assert_eq!(
            second
                .verify_step(
                    &MembershipAuthorization::Management(ManagementAction::Remove(id(&target))),
                    &change.commit
                )
                .err(),
            Some("revocation requires a signed order")
        );
        // Another valid order for the same removal is not the one committed.
        let other = second
            .issue_revocation(RevocationKind::Remove, id(&target))
            .unwrap();
        assert_eq!(
            second
                .verify_step(
                    &MembershipAuthorization::Revocation(OrderStep::new(other)),
                    &change.commit
                )
                .err(),
            Some("revocation commit does not carry its order")
        );
        second.verify_step(&change.authorization, &change.commit).unwrap();
    }

    /// ADR A2 T6 (security part): a Remove issued before its issuer was
    /// demoted still applies. The anchor decides, not the current roles.
    #[test]
    fn an_order_stays_valid_after_its_issuer_is_demoted() {
        let (admin, members) = team(3);
        let [second, target, carrier] = <[Workspace; 3]>::try_from(members).ok().unwrap();
        let promotion = admin
            .prepare_management(ManagementAction::Promote(id(&second)))
            .unwrap();
        let [second, target, carrier] =
            [&second, &target, &carrier].map(|m| follow(m, &promotion));
        let admin = promotion.workspace;
        let order = admin
            .issue_revocation(RevocationKind::Remove, id(&target))
            .unwrap();
        let at_anchor = carrier.public_checkpoint().unwrap();
        let demotion = second
            .prepare_management(ManagementAction::Demote(id(&admin)))
            .unwrap();
        let [carrier, target, admin] = [&carrier, &target, &admin].map(|m| follow(m, &demotion));
        let second = demotion.workspace;
        // Without a proof the anchor is not this state.
        assert_eq!(
            carrier.prepare_revocation(&OrderStep::new(order.clone())).err(),
            Some("revocation order needs an anchor proof")
        );
        let step = OrderStep::with_proof(
            order,
            AnchorProof {
                checkpoint: at_anchor,
                winning: vec![(demotion.authorization.clone(), demotion.commit.clone())],
                losing: vec![],
            },
        );
        let change = carrier.prepare_revocation(&step).unwrap();
        for verifier in [&second, &admin] {
            let after = follow(verifier, &change);
            assert!(after.member_roster().unwrap().iter().all(|m| m.id != id(&target)));
        }
        assert!(removed(&target, &change));
        // The step round-trips through history and restore.
        let records = change.workspace.export_records().unwrap();
        Workspace::restore_records(carrier.endpoint(), carrier.id(), &records).unwrap();
    }

    /// ADR A2 T8b (security part): a Remove issued on the losing branch
    /// after the fork point is accepted on the winner by its anchor proof.
    #[test]
    fn an_order_from_a_losing_branch_validates_by_its_proof() {
        let (admin, members) = team(4);
        let [second, target, carrier, spare] = <[Workspace; 4]>::try_from(members).ok().unwrap();
        let promotion = admin
            .prepare_management(ManagementAction::Promote(id(&second)))
            .unwrap();
        let [second, target, carrier, spare] =
            [&second, &target, &carrier, &spare].map(|m| follow(m, &promotion));
        let admin = promotion.workspace;
        let fork = carrier.public_checkpoint().unwrap();
        // Two administrators commit at the same epoch.
        let winner = second
            .prepare_management(ManagementAction::Promote(id(&carrier)))
            .unwrap();
        let loser = admin
            .prepare_management(ManagementAction::Promote(id(&spare)))
            .unwrap();
        // On the losing branch, the admin issues a Remove after the fork.
        let order = loser
            .workspace
            .issue_revocation(RevocationKind::Remove, id(&target))
            .unwrap();
        assert_eq!(order.anchor_epoch, loser.workspace.epoch());
        let [carrier, target, admin] = [&carrier, &target, &admin].map(|m| follow(m, &winner));
        let proof = |winning: &PreparedManagement, losing: Vec<&PreparedManagement>| AnchorProof {
            checkpoint: fork.clone(),
            winning: vec![(winning.authorization.clone(), winning.commit.clone())],
            losing: losing
                .into_iter()
                .map(|p| (p.authorization.clone(), p.commit.clone()))
                .collect(),
        };
        // A proof must reach this state and the order anchor.
        assert_eq!(
            carrier
                .prepare_revocation(&OrderStep::with_proof(order.clone(), proof(&loser, vec![&loser])))
                .err(),
            Some("anchor proof does not reach this state")
        );
        assert_eq!(
            carrier
                .prepare_revocation(&OrderStep::with_proof(order.clone(), proof(&winner, vec![])))
                .err(),
            Some("anchor proof does not reach the order anchor")
        );
        let change = carrier
            .prepare_revocation(&OrderStep::with_proof(order, proof(&winner, vec![&loser])))
            .unwrap();
        for verifier in [&winner.workspace, &admin] {
            follow(verifier, &change);
        }
        assert!(removed(&target, &change));
        // The fork key class is Removal.
        assert_eq!(
            crate::fork_key(&change.authorization, &change.commit).class(),
            crate::ForkClass::Removal
        );
    }

    /// ADR A2 T8b (window part): an order older than ORDER_WINDOW epochs is
    /// rejected on every node; one at the edge is accepted.
    #[test]
    fn an_order_older_than_the_window_is_rejected() {
        let (admin, members) = team(2);
        let [carrier, target] = <[Workspace; 2]>::try_from(members).ok().unwrap();
        let order = admin
            .issue_revocation(RevocationKind::Remove, id(&target))
            .unwrap();
        let checkpoint = carrier.public_checkpoint().unwrap();
        let (mut admin, mut carrier) = (admin, carrier);
        let mut steps = Vec::new();
        for n in 0..=ORDER_WINDOW {
            let action = if n % 2 == 0 {
                ManagementAction::Promote(id(&carrier))
            } else {
                ManagementAction::Demote(id(&carrier))
            };
            let change = admin.prepare_management(action).unwrap();
            carrier = follow(&carrier, &change);
            steps.push((change.authorization.clone(), change.commit.clone()));
            admin = change.workspace;
            if steps.len() as u64 == ORDER_WINDOW {
                // At the edge of the window: valid.
                let step = OrderStep::with_proof(
                    order.clone(),
                    AnchorProof {
                        checkpoint: checkpoint.clone(),
                        winning: steps.clone(),
                        losing: vec![],
                    },
                );
                let change = carrier.prepare_revocation(&step).unwrap();
                admin
                    .verify_step(&change.authorization, &change.commit)
                    .unwrap();
            }
        }
        assert_eq!(carrier.epoch() - order.anchor_epoch, ORDER_WINDOW + 1);
        // One epoch later the order is out of its window. The proof cannot
        // carry more than ORDER_WINDOW steps either.
        let step = OrderStep::with_proof(
            order,
            AnchorProof {
                checkpoint,
                winning: steps[1..].to_vec(),
                losing: vec![],
            },
        );
        assert_eq!(
            carrier.prepare_revocation(&step).err(),
            Some("revocation order is outside its window")
        );
    }
}
