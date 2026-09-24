//! Native network composition. Payloads and topics remain application-independent.
use super::*;
use arachne_routing::PublicationContext;

/// The session's publisher log, or a new one for the owner's current epoch.
fn publisher_or_new(
    session: &Session,
    owner: &arachne_security::Workspace,
) -> Result<arachne_delivery::PublisherLog, String> {
    match &session.delivery.publisher {
        Some(publisher) => Ok(publisher.clone()),
        None => arachne_delivery::PublisherLog::new(owner).map_err(str::to_owned),
    }
}

/// B7e: when staging moved a direct scope floor past a gap, report the
/// sequences given up as `missing_count`, as an explicit miss does.
fn report_missed(
    session: &Session,
    candidate: Option<&arachne_delivery::inbox::ObjectInbox>,
    value: &mut Value,
) {
    let before = session
        .delivery.inbox
        .as_ref()
        .map_or(0, arachne_delivery::inbox::ObjectInbox::missed_direct);
    let missed = candidate
        .map_or(0, arachne_delivery::inbox::ObjectInbox::missed_direct)
        .saturating_sub(before);
    if missed > 0 {
        value["missing_count"] = json!(missed);
    }
}

/// Stage only a locally requested, verified range; no caller-supplied reply bytes.
pub(super) fn stage_recovery(session: &mut Session, retain_until: u64) -> Result<Value, String> {
    let ready = session
        .recovery.ready_range
        .as_ref()
        .ok_or("no recovery range ready")?;
    check_recovery_policy(
        session,
        ready.peer,
        ready.query.author,
        ready.query.workspace,
        ready.query.epoch,
        ready.query.policy_revision,
        &ready.query.topics,
    )?;
    let owner = session
        .workspace
        .as_ref()
        .ok_or("session has no workspace")?;
    let key = session
        .storage_key
        .as_ref()
        .ok_or("session has no protected root key")?;
    let publisher = publisher_or_new(session, owner)?;
    let fresh;
    let inbox = match session.delivery.inbox.as_ref() {
        Some(inbox) => inbox,
        None => {
            fresh = arachne_delivery::inbox::ObjectInbox::new(owner.id(), owner.epoch());
            &fresh
        }
    };
    {
        if ready.automatic {
            let progress = inbox.recovery_progress(
                ready.query.author,
                ready.query.epoch,
                &ready.query.topics,
            );
            if ready.query.through <= progress {
                session.recovery.ready_range = None;
                return Ok(json!({"state":"recovery_already_covered"}));
            }
            if ready.query.after != progress {
                return Err("recovery range does not continue accepted progress".into());
            }
        }
        let offer = match arachne_delivery::wire::verify_reply(owner, &ready.query, &ready.reply)
            .map_err(str::to_owned)?
        {
            arachne_delivery::wire::RangeReply::Offered(offer) => offer,
            arachne_delivery::wire::RangeReply::Rejected(e) => return Err(e.to_string()),
        };
        let mut next = inbox.clone();
        if retain_until != 0 {
            let now = arachne_delivery::UnixSeconds::now()?;
            next = next
                .retain_range(owner, &ready.query, &ready.reply, retain_until, now)
                .map_err(str::to_owned)?;
        }
        let mut count = 0;
        // B7b: the whole range is verified above. Automatic recovery admits
        // the longest in-order prefix that fits the pending bounds and claims
        // progress only through its last record. The first refused record and
        // all after it are not recorded; a later request after the
        // application drains brings them again.
        let mut covered = ready.query.after;
        let mut stopped = false;
        for packet in offer.packets() {
            let live = packet
                .ciphertext
                .starts_with(b"DFVL")
                .then(|| arachne_delivery::current::LiveCurrentPacket::from_wire(&packet.ciphertext))
                .transpose()
                .map_err(str::to_owned)?;
            let ciphertext = if let Some(live) = &live {
                let (context, ciphertext) = PublicationContext::unpack(
                    packet.context.workspace,
                    packet.context.revision,
                    packet.context.topic.clone(),
                    &live.packet,
                )
                .map_err(str::to_owned)?;
                if context != packet.context {
                    return Err("retained current publication context mismatch".into());
                }
                ciphertext
            } else {
                packet.ciphertext.as_slice()
            };
            let aad = live.as_ref().map_or_else(
                || packet.context.authenticated_bytes(),
                |live| live.metadata.authenticated_context(&packet.context),
            );
            let authenticated = owner
                .unprotect_object(
                    packet.context.topic.namespace().as_bytes(),
                    &aad,
                    ciphertext,
                )
                .map_err(str::to_owned)?;
            offer
                .verify_origin(&authenticated.message)
                .map_err(str::to_owned)?;
            let staged = match live {
                Some(ref live) => {
                    next.stage_live_current(owner, &packet.context, live.metadata, ciphertext)
                }
                None => next.stage(owner, &packet.context, ciphertext),
            };
            let staged = match staged {
                Err(error)
                    if ready.automatic
                        && arachne_delivery::inbox::drains_with_application(error) =>
                {
                    stopped = true;
                    break;
                }
                staged => staged.map_err(str::to_owned)?,
            };
            match staged {
                arachne_delivery::inbox::InboxStage::Prepared(candidate) => {
                    next = *candidate;
                    count += 1;
                }
                arachne_delivery::inbox::InboxStage::Duplicate => (),
                arachne_delivery::inbox::InboxStage::OutsideWindow => {
                    return Err("recovered object outside receive window".into());
                }
            }
            covered = packet
                .context
                .sequence
                .ok_or("recovered publication lacks sequence")?
                .get();
        }
        if !stopped {
            covered = ready.query.through;
        }
        if ready.automatic && covered > ready.query.after {
            next = next
                .accept_recovery_prefix(owner, &ready.query, &ready.reply, covered)
                .map_err(str::to_owned)?;
        }
        if count == 0 && retain_until == 0 && !ready.automatic {
            session.recovery.ready_range = None;
            return Ok(json!({"state":"recovery_no_new_objects"}));
        }
        if ready.automatic && covered == ready.query.after && retain_until == 0 {
            // Nothing fits until the application drains this author's
            // pending objects. No progress is claimed; request again later.
            session.recovery.ready_range = None;
            return Ok(json!({"state":"recovery_awaiting_application",
                "accepted_through":covered, "accepted_progress":false}));
        }
        let snapshot = seal_state(
            session.records.is_some(),
            owner,
            key,
            Some(&publisher),
                Some(&next),
        ).map_err(crate::errors::text)?;
        let candidate = owner.provisional_copy().map_err(str::to_owned)?;
        let mut value = json!({"workspace":owner.id(), "snapshot":snapshot, "state":"awaiting_recovery_save",
            "publication_count":count, "durable":false, "accepted_progress":false});
        if ready.automatic {
            value["accepted_through"] = json!(covered);
        }
        report_missed(session, Some(&next), &mut value);
        session.transition.staged = Some(StagedWorkspace {
            workspace: candidate,
            publisher: Some(publisher),
                inbox: Some(next),
            snapshot,
            transition: WorkspaceTransition::InboxRecovery { count },
        });
        session.recovery.ready_range = None;
        Ok(value)
    }
}

pub(super) fn stage_direct_recovery(session: &mut Session) -> Result<Value, String> {
    let ready = session
        .recovery.ready_direct_range
        .as_ref()
        .ok_or("no direct recovery range ready")?;
    check_recovery_policy(
        session,
        ready.peer,
        ready.query.author,
        ready.query.workspace,
        ready.query.epoch,
        ready.query.policy_revision,
        &BTreeSet::from([ready.query.topic.clone()]),
    )?;
    let owner = session
        .workspace
        .as_ref()
        .ok_or("session has no workspace")?;
    let key = session
        .storage_key
        .as_ref()
        .ok_or("session has no protected root key")?;
    // B7c: a partial range is admitted as its in-order prefix; the stream
    // keeps its gap for the rest. When nothing fits, nothing is staged.
    let (next, count) = match session
        .delivery.inbox
        .as_ref()
        .ok_or("no object delivery state")?
        .stage_direct_range(owner, &ready.query, &ready.reply)
    {
        Err(error) if arachne_delivery::inbox::drains_with_application(error) => {
            session.recovery.ready_direct_range = None;
            return Ok(json!({"state":"direct_recovery_awaiting_application",
                "accepted_progress":false}));
        }
        staged => staged.map_err(str::to_owned)?,
    };
    if count == 0 {
        session.recovery.ready_direct_range = None;
        return Ok(json!({"state":"direct_recovery_already_covered"}));
    }
    let publisher = publisher_or_new(session, owner)?;
    let snapshot = seal_state(
        session.records.is_some(),
        owner,
        key,
        Some(&publisher),
        Some(&next),
    ).map_err(crate::errors::text)?;
    let candidate = owner.provisional_copy().map_err(str::to_owned)?;
    let mut value = json!({"workspace":owner.id(), "snapshot":snapshot,
        "state":"awaiting_recovery_save", "publication_count":count,
        "durable":false, "accepted_progress":false});
    report_missed(session, Some(&next), &mut value);
    session.transition.staged = Some(StagedWorkspace {
        workspace: candidate,
        publisher: Some(publisher),
        inbox: Some(next),
        snapshot,
        transition: WorkspaceTransition::InboxRecovery { count },
    });
    session.recovery.ready_direct_range = None;
    Ok(value)
}

pub(super) fn stage_direct_miss(session: &mut Session) -> Result<Value, String> {
    let query = session
        .recovery.direct_miss
        .as_ref()
        .ok_or("no exhausted direct recovery ready")?;
    let owner = session
        .workspace
        .as_ref()
        .ok_or("session has no workspace")?;
    let key = session
        .storage_key
        .as_ref()
        .ok_or("session has no protected root key")?;
    let (next, missing) = session
        .delivery.inbox
        .as_ref()
        .ok_or("no object delivery state")?
        .skip_direct_gap(owner, query)
        .map_err(str::to_owned)?;
    let publisher = publisher_or_new(session, owner)?;
    let snapshot = seal_state(
        session.records.is_some(),
        owner,
        key,
        Some(&publisher),
        Some(&next),
    ).map_err(crate::errors::text)?;
    let candidate = owner.provisional_copy().map_err(str::to_owned)?;
    let value = json!({"workspace":owner.id(), "snapshot":snapshot,
        "state":"awaiting_recovery_save", "missing_count":missing,
        "durable":false, "accepted_progress":false});
    session.transition.staged = Some(StagedWorkspace {
        workspace: candidate,
        publisher: Some(publisher),
        inbox: Some(next),
        snapshot,
        transition: WorkspaceTransition::DirectMiss { missing },
    });
    session.recovery.direct_miss = None;
    Ok(value)
}

