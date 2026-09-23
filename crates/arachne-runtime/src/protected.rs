//! Native network composition. Payloads and topics remain application-independent.
use super::*;
use arachne_routing::PublicationContext;

pub(super) fn stage(session: &mut Session, request: Request) -> Result<Value, String> {
    let owner = session
        .workspace
        .as_ref()
        .ok_or("session has no workspace")?;
    let key = session
        .storage_key
        .as_ref()
        .ok_or("session has no protected root key")?;
    let incoming = if matches!(request, Request::PollProtected {}) {
        // Bounded drain of local echoes. ATAK already owns its own outgoing
        // event; MLS cannot decrypt its own sent application ciphertext.
        let mut incoming = None;
        for _ in 0..256 {
            match session.receiver.try_recv() {
                Ok(message) if message.sender == session.node.id() => continue,
                Ok(message) => {
                    incoming = Some(message);
                    break;
                }
                Err(mpsc::error::TryRecvError::Empty) => return Ok(Value::Null),
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    return Err("event receiver closed".into());
                }
            }
        }
        if incoming.is_none() {
            return Ok(Value::Null);
        }
        incoming
    } else {
        None
    };
    let mut candidate = owner.provisional_copy().map_err(str::to_owned)?;
    let mut publisher = session.publisher.clone();
    let mut received = session.received.clone();
    let mut inbox = session.inbox.clone();
    let (transition, state) = match request {
        Request::StageNetworkPublication {
            revision,
            topic,
            id,
            payload,
            recipients,
            current,
            bulk,
        } => {
            if bulk && current.is_some() {
                return Err("current publication cannot be bulk".into());
            }
            if !recipients.is_empty()
                && (recipients.len() > 64 || recipients.windows(2).any(|pair| pair[0] >= pair[1]))
            {
                return Err("invalid direct recipient scope".into());
            }
            let self_member = owner
                .member()
                .ok_or("publisher requires member identity")?
                .id();
            if recipients.contains(&self_member) {
                return Err("direct recipient cannot be sender".into());
            }
            let current = current.map(|value| arachne_delivery::current::CurrentMetadata {
                selector: value.selector,
                replacement_key: value.replacement_key,
                expires_at: value.expires_at,
                tombstone: value.tombstone,
            });
            let delivery = match current {
                Some(current) => arachne_node::DeliveryClass::Current {
                    replacement_key: current.replacement_key,
                },
                None if bulk => arachne_node::DeliveryClass::Bulk,
                None => arachne_node::DeliveryClass::Critical,
            };
            if current.is_some() && (!recipients.is_empty() || inbox.is_none()) {
                return Err("current values require group object delivery".into());
            }
            let mut endpoints = if recipients.is_empty() {
                Vec::new()
            } else {
                owner
                    .endpoints_for_members(&recipients)
                    .map_err(str::to_owned)?
            };
            endpoints.sort_unstable();
            let topic = Topic::new(topic).map_err(|e| e.to_string())?;
            let context = PublicationContext {
                sequence: if recipients.is_empty() {
                    Some(
                        std::num::NonZeroU64::new(
                            publisher
                                .as_ref()
                                .map_or(0, |log| log.head())
                                .checked_add(1)
                                .ok_or("publisher sequence exhausted")?,
                        )
                        .unwrap(),
                    )
                } else if let Some(inbox) = inbox.as_ref() {
                    Some(
                        inbox
                            .next_direct_sequence(owner, revision, &topic, &recipients)
                            .map_err(str::to_owned)?,
                    )
                } else {
                    None
                },
                workspace: owner.id(),
                revision,
                topic,
                id,
            };
            let aad = if let Some(current) = current {
                current.authenticated_context(&context)
            } else if recipients.is_empty() {
                context.authenticated_bytes()
            } else {
                context
                    .direct_authenticated_bytes(&recipients)
                    .map_err(str::to_owned)?
            };
            // A direct publication cannot advance the shared MLS application
            // ratchet: unselected members would miss that generation. The
            // authenticated object envelope has independent sender counters and
            // is carried only on the selected Iroh connections.
            let ciphertext = if !recipients.is_empty() || inbox.is_some() {
                candidate.protect_object(&aad, &payload)
            } else {
                candidate.protect_application(&aad, &payload)
            }
            .map_err(str::to_owned)?;
            // Start retention with the first routed publication after activation.
            // No coverage for pre-activation data or old epochs is advertised.
            if recipients.is_empty() && publisher.is_none() {
                publisher = Some(arachne_delivery::PublisherLog::new(
                    owner.id(),
                    owner
                        .member()
                        .ok_or("publisher requires member identity")?
                        .id(),
                    owner.epoch(),
                ));
            }
            let packet = context.packet(&ciphertext).map_err(str::to_owned)?;
            if let Some(current) = current {
                inbox = Some(
                    inbox
                        .as_ref()
                        .ok_or("current values require object delivery")?
                        .stage_current(
                            &candidate,
                            context.clone(),
                            current.selector,
                            current.replacement_key,
                            current.expires_at,
                            current.tombstone,
                            packet.clone(),
                        )
                        .map_err(str::to_owned)?,
                );
            }
            let packet = match current {
                Some(metadata) => arachne_delivery::current::LiveCurrentPacket { metadata, packet }
                    .to_wire()
                    .map_err(str::to_owned)?,
                None => packet,
            };
            if !recipients.is_empty() && context.sequence.is_some() {
                inbox = Some(
                    inbox
                        .as_ref()
                        .ok_or("direct recovery requires object delivery")?
                        .stage_sent_direct(&candidate, &context, &recipients, &ciphertext)
                        .map_err(str::to_owned)?,
                );
            }
            if recipients.is_empty() {
                publisher
                    .as_mut()
                    .unwrap()
                    .append(
                        context.clone(),
                        if current.is_some() {
                            packet.clone()
                        } else {
                            ciphertext
                        },
                    )
                    .map_err(str::to_owned)?;
            }
            (
                WorkspaceTransition::RoutedPublication(
                    context, delivery, packet, endpoints, recipients,
                ),
                "awaiting_publication_save",
            )
        }
        Request::PollProtected {} => {
            let message = incoming.expect("protected poll has an incoming packet");
            if message.workspace != owner.id() {
                return Err("wrong workspace".into());
            }
            let (current, packet) = if message.payload.starts_with(b"DFVL") {
                let live = arachne_delivery::current::LiveCurrentPacket::from_wire(&message.payload)
                    .map_err(str::to_owned)?;
                (Some(live.metadata), live.packet)
            } else {
                (None, message.payload)
            };
            let (context, ciphertext) = PublicationContext::unpack(
                message.workspace,
                message.revision,
                message.topic,
                &packet,
            )
            .map_err(str::to_owned)?;
            if current.is_some() && (!message.recipients.is_empty() || inbox.is_none()) {
                return Err("current values require group object delivery".into());
            }
            if !message.recipients.is_empty() {
                let member = owner
                    .member()
                    .ok_or("direct receiver lacks member identity")?
                    .id();
                if message.recipients.binary_search(&member).is_err() {
                    return Err("direct publication excludes local member".into());
                }
            }
            let aad = if let Some(current) = current {
                current.authenticated_context(&context)
            } else if message.recipients.is_empty() {
                context.authenticated_bytes()
            } else {
                context
                    .direct_authenticated_bytes(&message.recipients)
                    .map_err(str::to_owned)?
            };
            let now = if current.is_some() {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|_| "system clock is before Unix epoch")?
                    .as_secs()
            } else {
                0
            };
            if let Some(active_inbox) = inbox.as_ref() {
                let authenticated = owner
                    .unprotect_object(&aad, ciphertext)
                    .map_err(str::to_owned)?;
                if authenticated.message.endpoint != message.sender {
                    return Err("direct author mismatch".into());
                }
                let stage = match current {
                    Some(metadata) => {
                        active_inbox.stage_live_current(owner, &context, metadata, now, ciphertext)
                    }
                    None => active_inbox.stage_with_recipients(
                        owner,
                        &context,
                        &message.recipients,
                        ciphertext,
                    ),
                }
                .map_err(str::to_owned)?;
                match stage {
                    arachne_delivery::inbox::InboxStage::Prepared(next) => inbox = Some(*next),
                    arachne_delivery::inbox::InboxStage::Duplicate => return Ok(Value::Null),
                    arachne_delivery::inbox::InboxStage::OutsideWindow => {
                        return Err("object outside receive window".into());
                    }
                }
                (WorkspaceTransition::Inbox, "awaiting_reception_save")
            } else {
                if let Some(journal) = received.as_ref() {
                    let author = owner
                        .member_id_for_endpoint(message.sender)
                        .map_err(str::to_owned)?;
                    match journal
                        .check(author, &context, ciphertext)
                        .map_err(str::to_owned)?
                    {
                        arachne_delivery::receive::ReceiveStatus::Known => return Ok(Value::Null),
                        arachne_delivery::receive::ReceiveStatus::Conflicting => {
                            return Err("conflicting received publication".into());
                        }
                        arachne_delivery::receive::ReceiveStatus::Unseen => (),
                    }
                }
                let plaintext = if message.recipients.is_empty() {
                    candidate
                        .unprotect_application(&aad, ciphertext)
                        .map_err(str::to_owned)?
                } else {
                    candidate
                        .unprotect_object(&aad, ciphertext)
                        .map_err(str::to_owned)?
                        .message
                };
                if plaintext.endpoint != message.sender {
                    return Err("direct author mismatch".into());
                }
                if let Some(journal) = received.as_mut() {
                    journal
                        .record_verified(&plaintext, &context, ciphertext)
                        .map_err(str::to_owned)?;
                }
                (
                    WorkspaceTransition::RoutedReception(context, plaintext, message.recipients),
                    "awaiting_reception_save",
                )
            }
        }
        _ => unreachable!(),
    };
    let snapshot = seal_state(
        session.records.is_some(),
        &candidate,
        key,
        publisher.as_ref(),
        received.as_ref(),
        inbox.as_ref(),
    )?;
    let value =
        json!({"workspace":candidate.id(), "snapshot":snapshot, "state":state, "durable":false});
    session.staged_workspace = Some(StagedWorkspace {
        publisher,
        received,
        inbox,
        transition,
        workspace: candidate,
        snapshot,
    });
    Ok(value)
}

/// Stage only a locally requested, verified range; no caller-supplied reply bytes.
pub(super) fn stage_recovery(session: &mut Session, retain_until: u64) -> Result<Value, String> {
    let ready = session
        .ready_range
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
    let publisher = session
        .publisher
        .clone()
        .unwrap_or(arachne_delivery::PublisherLog::new(
            owner.id(),
            owner
                .member()
                .ok_or("publisher requires member identity")?
                .id(),
            owner.epoch(),
        ));
    if let Some(inbox) = session.inbox.as_ref() {
        if ready.automatic {
            let progress = inbox.recovery_progress(ready.query.author, &ready.query.topics);
            let received_through = inbox
                .group_received_through(owner, ready.query.author, &ready.query.topics)
                .map_err(str::to_owned)?
                .unwrap_or(progress);
            if ready.query.through <= received_through {
                session.ready_range = None;
                return Ok(json!({"state":"recovery_already_covered"}));
            }
            if ready.query.after < progress || ready.query.after > received_through {
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
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "system clock is before Unix epoch")?
            .as_secs();
        if retain_until != 0 {
            next = next
                .retain_range(owner, &ready.query, &ready.reply, retain_until, now)
                .map_err(str::to_owned)?;
        }
        let mut count = 0;
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
                .unprotect_object(&aad, ciphertext)
                .map_err(str::to_owned)?;
            offer
                .verify_origin(&authenticated.message)
                .map_err(str::to_owned)?;
            let staged = match live {
                Some(ref live) => {
                    next.stage_live_current(owner, &packet.context, live.metadata, now, ciphertext)
                }
                None => next.stage(owner, &packet.context, ciphertext),
            }
            .map_err(str::to_owned)?;
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
        }
        if ready.automatic {
            next = next
                .accept_recovery_coverage(owner, &ready.query, &ready.reply)
                .map_err(str::to_owned)?;
        }
        if count == 0 && retain_until == 0 && !ready.automatic {
            session.ready_range = None;
            return Ok(json!({"state":"recovery_no_new_objects"}));
        }
        let snapshot = seal_state(
            session.records.is_some(),
            owner,
            key,
            Some(&publisher),
            session.received.as_ref(),
            Some(&next),
        )?;
        let candidate = owner.provisional_copy().map_err(str::to_owned)?;
        let value = json!({"workspace":owner.id(), "snapshot":snapshot, "state":"awaiting_recovery_save",
            "publication_count":count, "durable":false, "accepted_progress":false});
        session.staged_workspace = Some(StagedWorkspace {
            workspace: candidate,
            publisher: Some(publisher),
            received: session.received.clone(),
            inbox: Some(next),
            snapshot,
            transition: WorkspaceTransition::InboxRecovery { count },
        });
        session.ready_range = None;
        return Ok(value);
    }
    if retain_until != 0 {
        return Err("retained third-holder recovery requires object delivery".into());
    }
    let received = session.received.clone().unwrap_or_else(|| {
        arachne_delivery::receive::ReceiveJournal::new(owner.id(), owner.epoch())
    });
    let stage = if session.records.is_some() {
        received.prepare_recovery(owner, &publisher, &ready.query, &ready.reply)
    } else {
        received.stage_recovery(owner, key, &publisher, &ready.query, &ready.reply)
    }
    .map_err(str::to_owned)?;
    let value = match stage {
        arachne_delivery::receive::RecoveryStage::AlreadyCovered => {
            json!({"state":"recovery_already_covered"})
        }
        arachne_delivery::receive::RecoveryStage::Rejected(error) => return Err(error.to_string()),
        arachne_delivery::receive::RecoveryStage::Prepared(mut staged) => {
            if session.records.is_some() {
                staged.snapshot = persistence::candidate_token()?;
            }
            let value = json!({"workspace":staged.owner.id(), "snapshot":staged.snapshot,
                "state":"awaiting_recovery_save", "publication_count":staged.publications.len(),
                "already_received":staged.already_received, "durable":false, "accepted_progress":false});
            session.staged_workspace = Some(StagedWorkspace {
                publisher: Some(publisher),
                received: Some(staged.received),
                inbox: session.inbox.clone(),
                transition: WorkspaceTransition::Recovery(staged.publications),
                workspace: staged.owner,
                snapshot: staged.snapshot,
            });
            value
        }
    };
    session.ready_range = None;
    Ok(value)
}

pub(super) fn stage_direct_recovery(session: &mut Session) -> Result<Value, String> {
    let ready = session
        .ready_direct_range
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
    let (next, count) = session
        .inbox
        .as_ref()
        .ok_or("object delivery not enabled")?
        .stage_direct_range(owner, &ready.query, &ready.reply)
        .map_err(str::to_owned)?;
    if count == 0 {
        session.ready_direct_range = None;
        return Ok(json!({"state":"direct_recovery_already_covered"}));
    }
    let publisher = session
        .publisher
        .clone()
        .unwrap_or(arachne_delivery::PublisherLog::new(
            owner.id(),
            owner.member().ok_or("member required")?.id(),
            owner.epoch(),
        ));
    let snapshot = seal_state(
        session.records.is_some(),
        owner,
        key,
        Some(&publisher),
        session.received.as_ref(),
        Some(&next),
    )?;
    let candidate = owner.provisional_copy().map_err(str::to_owned)?;
    let value = json!({"workspace":owner.id(), "snapshot":snapshot,
        "state":"awaiting_recovery_save", "publication_count":count,
        "durable":false, "accepted_progress":false});
    session.staged_workspace = Some(StagedWorkspace {
        workspace: candidate,
        publisher: Some(publisher),
        received: session.received.clone(),
        inbox: Some(next),
        snapshot,
        transition: WorkspaceTransition::InboxRecovery { count },
    });
    session.ready_direct_range = None;
    Ok(value)
}

pub(super) fn stage_direct_miss(session: &mut Session) -> Result<Value, String> {
    let query = session
        .direct_miss
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
        .inbox
        .as_ref()
        .ok_or("object delivery not enabled")?
        .skip_direct_gap(owner, query)
        .map_err(str::to_owned)?;
    let publisher = session
        .publisher
        .clone()
        .unwrap_or(arachne_delivery::PublisherLog::new(
            owner.id(),
            owner.member().ok_or("member required")?.id(),
            owner.epoch(),
        ));
    let snapshot = seal_state(
        session.records.is_some(),
        owner,
        key,
        Some(&publisher),
        session.received.as_ref(),
        Some(&next),
    )?;
    let candidate = owner.provisional_copy().map_err(str::to_owned)?;
    let value = json!({"workspace":owner.id(), "snapshot":snapshot,
        "state":"awaiting_recovery_save", "missing_count":missing,
        "durable":false, "accepted_progress":false});
    session.staged_workspace = Some(StagedWorkspace {
        workspace: candidate,
        publisher: Some(publisher),
        received: session.received.clone(),
        inbox: Some(next),
        snapshot,
        transition: WorkspaceTransition::DirectMiss { missing },
    });
    session.direct_miss = None;
    Ok(value)
}

/// All pending/ack operations share the existing exact-snapshot adoption guard.
pub(super) fn inbox_operation(session: &mut Session, request: Request) -> Result<Value, String> {
    let owner = session
        .workspace
        .as_ref()
        .ok_or("session has no workspace")?;
    let key = session
        .storage_key
        .as_ref()
        .ok_or("session has no protected root key")?;
    if let Request::PollPendingObject { deferred } = request {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "system clock is before Unix epoch")?
            .as_secs();
        return match session
            .inbox
            .as_ref()
            .ok_or("object delivery not enabled")?
            .pending_excluding_at(owner, &deferred, now)
            .map_err(str::to_owned)?
        {
            None => Ok(Value::Null),
            Some(p) => {
                let mut value = json!({"workspace":p.context.workspace, "revision":p.context.revision,
                "topic":p.context.topic.as_str(), "id":p.context.id, "sequence":p.context.sequence.map(|n| n.get()),
                "member":p.message.member, "endpoint":p.message.endpoint, "payload":p.message.payload, "counter":p.counter,
                "recipients":p.recipients});
                if let Some(current) = p.current {
                    value["current"] = json!({"selector":current.selector,
                        "replacement_key":current.replacement_key,
                        "expires_at":current.expires_at,
                        "tombstone":current.tombstone});
                }
                Ok(value)
            }
        };
    }
    let rejected = matches!(request, Request::StageObjectRejection { .. });
    let inbox = match request {
        Request::EnableObjectDelivery {} => {
            if session.inbox.is_some() {
                return Ok(json!({"state":"object_delivery_enabled"}));
            }
            arachne_delivery::inbox::ObjectInbox::new(owner.id(), owner.epoch())
        }
        Request::StageObjectAcknowledgement {
            member,
            topic,
            counter,
            id,
        } => session
            .inbox
            .as_ref()
            .ok_or("object delivery not enabled")?
            .acknowledge(
                member,
                &Topic::new(topic).map_err(|e| e.to_string())?,
                counter,
                id,
            )
            .map_err(str::to_owned)?,
        Request::StageObjectRejection {
            member,
            topic,
            counter,
            id,
        } => session
            .inbox
            .as_ref()
            .ok_or("object delivery not enabled")?
            .reject(
                member,
                &Topic::new(topic).map_err(|e| e.to_string())?,
                counter,
                id,
            )
            .map_err(str::to_owned)?,
        _ => unreachable!(),
    };
    let publisher = session
        .publisher
        .clone()
        .unwrap_or(arachne_delivery::PublisherLog::new(
            owner.id(),
            owner.member().ok_or("member required")?.id(),
            owner.epoch(),
        ));
    let snapshot = seal_state(
        session.records.is_some(),
        owner,
        key,
        Some(&publisher),
        session.received.as_ref(),
        Some(&inbox),
    )?;
    let candidate = owner.provisional_copy().map_err(str::to_owned)?;
    let value = json!({"workspace":owner.id(), "snapshot":snapshot, "state":"awaiting_reception_save", "durable":false});
    session.staged_workspace = Some(StagedWorkspace {
        workspace: candidate,
        publisher: Some(publisher),
        received: session.received.clone(),
        inbox: Some(inbox),
        transition: if rejected {
            WorkspaceTransition::InboxRejected
        } else {
            WorkspaceTransition::Inbox
        },
        snapshot,
    });
    Ok(value)
}
