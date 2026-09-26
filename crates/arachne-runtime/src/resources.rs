//! Metadata-only host operations. File work runs on native tasks, never while
//! holding the session/journal lock. Peer identity comes from accepted membership.
use arachne_node::resources::ResourceTicket;
use serde::Deserialize;
use arachne_api::{ApiError, ErrorCode};
use serde_json::{Value, json};

use crate::errors::{self, security};
use std::{collections::BTreeMap, path::PathBuf};
use tokio::{sync::watch, task::JoinHandle};

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Request {
    Prepare {
        member: [u8; 32],
        root: PathBuf,
        path: PathBuf,
    },
    Fetch {
        member: [u8; 32],
        root: PathBuf,
        path: PathBuf,
        ticket: ResourceTicket,
    },
    Poll {
        id: u64,
    },
    Cancel {
        id: u64,
    },
    Revoke {
        path: Option<PathBuf>,
    },
    Clear {
        root: PathBuf,
    },
}

struct Job {
    task: JoinHandle<Result<Value, String>>,
    progress: watch::Receiver<u64>,
}
impl Drop for Job {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[derive(Default)]
pub(super) struct Jobs {
    next: u64,
    jobs: BTreeMap<u64, Job>,
}

pub(super) fn execute(session: &mut super::Session, request: Request) -> Result<Value, ApiError> {
    let resources = session.node.resources();
    match request {
        Request::Poll { id } => {
            let job = session
                .resources
                .jobs
                .get(&id)
                .ok_or_else(|| ApiError::invalid_input("id", "unknown resource operation"))?;
            if !job.task.is_finished() {
                return Ok(json!({"state":"running", "bytes":*job.progress.borrow()}));
            }
            let mut job = session.resources.jobs.remove(&id).unwrap();
            return session
                .runtime
                .block_on(&mut job.task)
                .map_err(|error| ApiError::internal(error.to_string()))?
                .map_err(|error| ApiError::transport_failed(None, error));
        }
        Request::Cancel { id } => {
            session.resources.jobs.remove(&id);
            return Ok(json!({"state":"cancelled"}));
        }
        Request::Revoke { path } => {
            resources.revoke(path.as_deref());
            return Ok(json!({"state":"revoked"}));
        }
        _ => (),
    }
    if matches!(request, Request::Clear { .. }) {
        session.resources.jobs.clear();
    }
    if session.resources.jobs.len() >= 8 {
        return Err(ApiError::capacity_exceeded(
            "resource workers",
            8,
            "resource workers busy",
        ));
    }
    let (progress, receiver) = watch::channel(0);
    let owner = session
        .workspace
        .as_ref()
        .ok_or_else(errors::no_workspace)?;
    let workspace = owner.id();
    let revision = owner
        .epoch()
        .checked_add(1)
        .ok_or_else(|| ApiError::internal("workspace epoch overflow"))?;
    let task = match request {
        Request::Prepare { member, root, path } => {
            let peer = owner
                .endpoints_for_members(&[member])
                .map_err(security(ErrorCode::NotMember))?[0];
            session.runtime.spawn(async move {
                let ticket = resources
                    .prepare(&root, &path, workspace, revision, peer)
                    .await
                    .map_err(|error| error.to_string())?;
                Ok(json!({"state":"prepared", "ticket":ticket}))
            })
        }
        Request::Fetch {
            member,
            root,
            path,
            ticket,
        } => {
            let peer = owner
                .endpoints_for_members(&[member])
                .map_err(security(ErrorCode::NotMember))?[0];
            session.runtime.spawn(async move {
                let size = ticket.size;
                resources
                    .fetch(&root, &path, workspace, revision, peer, ticket, progress)
                    .await
                    .map_err(|error| error.to_string())?;
                Ok(json!({"state":"complete", "bytes":size}))
            })
        }
        Request::Clear { root } => session.runtime.spawn(async move {
            resources
                .clear_partial(&root)
                .await
                .map_err(|error| error.to_string())?;
            Ok(json!({"state":"cleared"}))
        }),
        _ => unreachable!(),
    };
    session.resources.next = session
        .resources
        .next
        .checked_add(1)
        .ok_or_else(|| ApiError::internal("resource operation overflow"))?;
    let id = session.resources.next;
    session.resources.jobs.insert(
        id,
        Job {
            task,
            progress: receiver,
        },
    );
    Ok(json!({"state":"started", "id":id}))
}
