//! Native persistence owns secrets; callers exchange only candidate tokens.
use super::*;
use arachne_security::{SecurityRecords, Workspace};
use arachne_store::Store;
use std::path::Path;
use zeroize::Zeroizing;

const TOKEN: &[u8] = b"runtime/token";
const PENDING: &[u8] = b"runtime/pending";
const JOIN_LIFECYCLE: &[u8] = b"runtime/join-lifecycle";
const ACTIVITY: &[u8] = b"runtime/activity";
const RESET: &[u8] = b"runtime/reset";
const REMOVED: &[u8] = b"runtime/removed";
const PUBLISHER: &[u8] = b"delivery/publisher";
const RECEIVED: &[u8] = b"delivery/received";
const INBOX: &[u8] = b"delivery/inbox";

pub(super) struct NativeStore {
    store: Store,
    committed: Vec<u8>,
}
impl NativeStore {
    pub(super) fn require_committed(&self, token: &[u8]) -> Result<(), String> {
        if token != self.committed {
            return Err("candidate has not been committed to native storage".into());
        }
        Ok(())
    }
    fn commit(&mut self, mut records: SecurityRecords, token: &[u8]) -> Result<(), String> {
        records.insert(TOKEN.to_vec(), Zeroizing::new(token.to_vec()));
        let deleted: Vec<_> = self
            .store
            .keys(b"")
            .filter(|name| !records.contains_key(*name))
            .map(<[u8]>::to_vec)
            .collect();
        let mut changes = Vec::new();
        for (name, value) in &records {
            if self.store.get(name).map_err(|e| e.to_string())?.as_deref() != Some(value.as_ref()) {
                changes.push((name.as_slice(), Some(value.as_slice())));
            }
        }
        changes.extend(deleted.iter().map(|name| (name.as_slice(), None)));
        self.store
            .commit(self.store.revision(), &changes)
            .map_err(|e| e.to_string())?;
        self.committed = token.to_vec();
        Ok(())
    }
}

pub(super) fn candidate_token() -> Result<Vec<u8>, String> {
    let mut token = vec![0; 37];
    token[..5].copy_from_slice(b"DFRC\x01");
    getrandom::getrandom(&mut token[5..]).map_err(|e| e.to_string())?;
    Ok(token)
}

fn active_records(
    owner: &Workspace,
    publisher: Option<&arachne_delivery::PublisherLog>,
    received: Option<&arachne_delivery::receive::ReceiveJournal>,
    inbox: Option<&arachne_delivery::inbox::ObjectInbox>,
    activity: &WorkspaceActivity,
) -> Result<SecurityRecords, String> {
    let mut records = owner.export_records().map_err(str::to_owned)?;
    records.insert(
        ACTIVITY.to_vec(),
        Zeroizing::new(serde_json::to_vec(activity).map_err(|error| error.to_string())?),
    );
    if let Some(inbox) = inbox {
        records.insert(
            INBOX.to_vec(),
            Zeroizing::new(
                inbox
                    .with_legacy_receipts(received)
                    .snapshot_with_publisher(owner, publisher.ok_or("inbox requires publisher")?)
                    .map_err(str::to_owned)?,
            ),
        );
    } else {
        if let Some(publisher) = publisher {
            let snapshot = publisher.snapshot();
            // Validate the same owner binding as legacy sealed persistence.
            arachne_delivery::PublisherLog::restore(
                owner.id(),
                owner.member().ok_or("member required")?.id(),
                owner.epoch(),
                &snapshot,
            )
            .map_err(str::to_owned)?;
            records.insert(PUBLISHER.to_vec(), Zeroizing::new(snapshot));
        }
        if let Some(received) = received {
            if publisher.is_none() {
                return Err("receive journal requires publisher".into());
            }
            let snapshot = received.snapshot();
            arachne_delivery::receive::ReceiveJournal::restore(owner.id(), owner.epoch(), &snapshot)
                .map_err(str::to_owned)?;
            records.insert(RECEIVED.to_vec(), Zeroizing::new(snapshot));
        }
    }
    Ok(records)
}

fn pending_records(session: &Session, pending: &arachne_security::PendingJoin) -> Result<SecurityRecords, String> {
    let bytes = pending
        .seal(session.storage_key.as_ref().ok_or("protected root required")?)
        .map_err(str::to_owned)?;
    let mut records = BTreeMap::from([(PENDING.to_vec(), Zeroizing::new(bytes))]);
    if let Some(lifecycle) = &session.join_lifecycle {
        records.insert(
            JOIN_LIFECYCLE.to_vec(),
            Zeroizing::new(serde_json::to_vec(lifecycle).map_err(|error| error.to_string())?),
        );
    }
    records.insert(
        ACTIVITY.to_vec(),
        Zeroizing::new(serde_json::to_vec(&session.activity).map_err(|error| error.to_string())?),
    );
    Ok(records)
}

fn idle(session: &Session) -> Result<(), String> {
    if session.records.is_some()
        || session.staged_workspace.is_some()
        || session.staged_removal.is_some()
        || session.inbound_admission.is_some()
        || session.membership_update.is_some()
        || session.cutoff.is_some()
        || session.current_view.is_some()
        || session.ready_current_view.is_some()
        || session.range.is_some()
        || session.ready_range.is_some()
        || !session.recovered.is_empty()
    {
        return Err("record storage requires an idle session".into());
    }
    Ok(())
}

/// Atomically migrate the current accepted owner and delivery state into an empty
/// record store. The host supplies a private path and protected storage root and
/// must retain its endpoint credential lock. Existing stores require restore;
/// never overwrite one with an older legacy snapshot or fall back on open failure.
/// A pending join may migrate too; admission atomically replaces its records.
/// Host route/unknown-outcome metadata remains separate and must be preserved.
pub fn enable_record_storage(handle: i64, path: &Path, root: &[u8; 32]) -> Result<(), String> {
    let shared = session(handle)?;
    let mut guard = shared.lock().map_err(|_| "node session unavailable")?;
    let session = guard.as_mut().ok_or("node is closed")?;
    idle(session)?;
    if session.storage_key.is_none() {
        return Err("protected endpoint root required".into());
    }
    let (workspace, records) = if let Some(owner) = &session.workspace {
        (
            owner.id(),
            active_records(
                owner,
                session.publisher.as_ref(),
                session.received.as_ref(),
                session.inbox.as_ref(),
                &session.activity,
            )?,
        )
    } else if let Some(pending) = &session.pending_join {
        (pending.workspace_id(), pending_records(session, pending)?)
    } else {
        return Err("session has no workspace or pending join".into());
    };
    let store = Store::open(path, root, workspace).map_err(|e| e.to_string())?;
    if store.revision() != 0 {
        return Err("record store already initialized; restore it".into());
    }
    let mut native = NativeStore {
        store,
        committed: Vec::new(),
    };
    native.commit(records, &candidate_token()?)?;
    session.records = Some(native);
    Ok(())
}

/// Commit the exact staged candidate, including counters and delivery state.
/// This does not adopt, send, reply or release application data. Retry after a
/// successful commit is idempotent; callers still invoke the matching adoption.
pub fn save_candidate(handle: i64, token: &[u8]) -> Result<(), String> {
    let shared = session(handle)?;
    let mut guard = shared.lock().map_err(|_| "node session unavailable")?;
    let session = guard.as_mut().ok_or("node is closed")?;
    commit_candidate(session, token)
}

/// Commit the exact staged candidate using the native store already attached to
/// this session. The lifecycle driver calls this before adoption, so Android
/// never becomes the authority for the save/adopt ordering.
pub(super) fn commit_candidate(session: &mut Session, token: &[u8]) -> Result<(), String> {
    let records = if let Some(staged) = &session.staged_workspace {
        if token != staged.snapshot {
            return Err("token does not match candidate".into());
        }
        let activity = if matches!(staged.transition, WorkspaceTransition::Join) {
            WorkspaceActivity {
                phase: WorkspacePhase::Active,
                reason: None,
            }
        } else {
            session.activity.clone()
        };
        active_records(
            &staged.workspace,
            staged.publisher.as_ref(),
            staged.received.as_ref(),
            staged.inbox.as_ref(),
            &activity,
        )?
    } else if let Some((removed, expected)) = &session.staged_removal {
        if token != expected {
            return Err("token does not match removal".into());
        }
        let bytes = removed
            .seal(
                session
                    .storage_key
                    .as_ref()
                    .ok_or("protected root required")?,
            )
            .map_err(str::to_owned)?;
        BTreeMap::from([(REMOVED.to_vec(), Zeroizing::new(bytes))])
    } else {
        return Err("session has no candidate".into());
    };
    let store = session
        .records
        .as_mut()
        .ok_or("native record storage not enabled")?;
    if store.require_committed(token).is_ok() {
        return Ok(());
    }
    store.commit(records, token)
}

/// Persist pending join routing before an Iroh admission exchange can leave the
/// endpoint. This makes an interrupted send retry the same attempt/peer.
pub(super) fn commit_pending_join(session: &mut Session) -> Result<(), String> {
    let pending = session.pending_join.as_ref().ok_or("session has no pending join")?;
    let records = pending_records(session, pending)?;
    let token = candidate_token()?;
    session
        .records
        .as_mut()
        .ok_or("native record storage not enabled")?
        .commit(records, &token)
}

/// Replace the native record set with an invalidation marker. The marker is
/// deliberately not restorable as a workspace; an adapter may then remove the
/// directory, but a crash between reset and cleanup cannot resurrect old state.
pub(super) fn reset_records(
    session: &mut Session,
    activity: &WorkspaceActivity,
) -> Result<(), String> {
    let records = BTreeMap::from([
        (
            RESET.to_vec(),
            Zeroizing::new(vec![b'D', b'F', b'R', b'S', 1]),
        ),
        (
            ACTIVITY.to_vec(),
            Zeroizing::new(serde_json::to_vec(activity).map_err(|error| error.to_string())?),
        ),
    ]);
    let token = candidate_token()?;
    session
        .records
        .as_mut()
        .ok_or("native record storage not enabled")?
        .commit(records, &token)
}

/// Restore only the authoritative native store into an empty endpoint session.
/// Failure must not trigger legacy fallback. Removal consumes the session.
pub fn restore_record_storage(
    handle: i64,
    path: &Path,
    root: &[u8; 32],
    workspace: [u8; 32],
) -> Result<Value, String> {
    let shared = session(handle)?;
    let mut guard = shared.lock().map_err(|_| "node session unavailable")?;
    let session = guard.as_mut().ok_or("node is closed")?;
    idle(session)?;
    if session.workspace.is_some() || session.pending_join.is_some() {
        return Err("session already owns a workspace".into());
    }
    // An absent authoritative store must never become a new empty database.
    std::fs::metadata(path).map_err(|e| e.to_string())?;
    let store = Store::open(path, root, workspace).map_err(|e| e.to_string())?;
    let get = |name: &[u8]| store.get(name).map_err(|e| e.to_string());
    let committed = get(TOKEN)?.ok_or("missing native commit token")?.to_vec();
    if committed.len() != 37 || !committed.starts_with(b"DFRC\x01") {
        return Err("invalid native commit token".into());
    }
    if get(RESET)?.is_some() {
        return Err("native record store was reset".into());
    }
    if let Some(bytes) = get(PENDING)? {
        if store.keys(b"").any(|name| {
            name != PENDING && name != TOKEN && name != JOIN_LIFECYCLE && name != ACTIVITY
        }) {
            return Err("pending store contains other lifecycle state".into());
        }
        let pending = arachne_security::PendingJoin::restore(
            session
                .storage_key
                .as_ref()
                .ok_or("protected root required")?,
            session.node.id(),
            workspace,
            &bytes,
        )
        .map_err(str::to_owned)?;
        let mut value = pending_metadata(&pending, session.node.id())?;
        value["durable"] = json!(true);
        let activity = get(ACTIVITY)?
            .map(|bytes| serde_json::from_slice::<WorkspaceActivity>(&bytes).map_err(|error| error.to_string()))
            .transpose()?
            .unwrap_or(WorkspaceActivity {
                phase: WorkspacePhase::Joining,
                reason: None,
            });
        if activity.phase != WorkspacePhase::Joining {
            return Err("pending store has invalid workspace activity".into());
        }
        value["activity"] = activity.projection();
        session.activity = activity;
        session.join_lifecycle = get(JOIN_LIFECYCLE)?
            .map(|bytes| {
                let lifecycle: JoinLifecycle =
                    serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
                lifecycle.validate()?;
                Ok::<JoinLifecycle, String>(lifecycle)
            })
            .transpose()?;
        session.pending_join = Some(pending);
        session.records = Some(NativeStore { store, committed });
        return Ok(value);
    }
    if let Some(bytes) = get(REMOVED)? {
        if store.keys(b"").count() != 2 {
            return Err("removed store contains active state".into());
        }
        let removed = arachne_security::RemovedMembership::restore(
            session
                .storage_key
                .as_ref()
                .ok_or("protected root required")?,
            session.node.id(),
            workspace,
            &bytes,
        )
        .map_err(str::to_owned)?;
        let value = json!({"workspace": workspace, "state":"removed", "epoch":removed.epoch(),
            "member":{"id":removed.member().id(),"display_name":removed.member().display_name()},
            "commit_digest":removed.commit_digest(), "workspace_ready":false,"durable":true});
        let ended = guard.take().ok_or("node is closed")?;
        drop(guard);
        shutdown_session(ended)?;
        return Ok(value);
    }
    for name in store.keys(b"") {
        if !name.starts_with(b"security/")
            && ![TOKEN, PUBLISHER, RECEIVED, INBOX, ACTIVITY].contains(&name)
        {
            return Err("unknown native runtime record".into());
        }
    }
    let security: SecurityRecords = store
        .keys(b"security/")
        .map(|name| Ok((name.to_vec(), get(name)?.ok_or("missing security record")?)))
        .collect::<Result<_, String>>()?;
    let owner = Workspace::restore_records(session.node.id(), workspace, &security)
        .map_err(str::to_owned)?;
    let (publisher, received, inbox) = if let Some(bytes) = get(INBOX)? {
        if get(PUBLISHER)?.is_some() || get(RECEIVED)?.is_some() {
            return Err("mixed delivery records".into());
        }
        let (publisher, inbox) =
            arachne_delivery::inbox::ObjectInbox::restore_snapshot(&owner, &bytes)
                .map_err(str::to_owned)?;
        let received = inbox.legacy_receipts().map_err(str::to_owned)?;
        (Some(publisher), received, Some(inbox))
    } else {
        let publisher = get(PUBLISHER)?
            .map(|bytes| {
                arachne_delivery::PublisherLog::restore(
                    workspace,
                    owner.member().ok_or("member required")?.id(),
                    owner.epoch(),
                    &bytes,
                )
            })
            .transpose()
            .map_err(str::to_owned)?;
        let received = get(RECEIVED)?
            .map(|bytes| {
                arachne_delivery::receive::ReceiveJournal::restore(workspace, owner.epoch(), &bytes)
            })
            .transpose()
            .map_err(str::to_owned)?;
        if received.is_some() && publisher.is_none() {
            return Err("receive journal requires publisher".into());
        }
        (publisher, received, None)
    };
    let value = json!({"workspace":workspace,"workspace_name":owner.workspace_name().map_err(str::to_owned)?,"epoch":owner.epoch(),"members":owner.member_count(),
        "member":member_metadata(&owner),"durable":true});
    let activity = get(ACTIVITY)?
        .map(|bytes| serde_json::from_slice::<WorkspaceActivity>(&bytes).map_err(|error| error.to_string()))
        .transpose()?
        .unwrap_or(WorkspaceActivity {
            phase: WorkspacePhase::Active,
            reason: None,
        });
    if !matches!(activity.phase, WorkspacePhase::Active | WorkspacePhase::Recovering) {
        return Err("active store has invalid workspace activity".into());
    }
    let mut value = value;
    value["activity"] = activity.projection();
    session.activity = activity;
    session.publisher = publisher;
    session.received = received;
    session.inbox = inbox;
    commit_workspace(session, owner);
    session.records = Some(NativeStore { store, committed });
    Ok(value)
}
