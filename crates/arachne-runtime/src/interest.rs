//! Immediate local interests and bounded, serialized remote announcements.
use crate::*;
use std::time::Instant;

const MAX_INTERESTS: usize = 64;
const RETRY_DELAY: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub(super) struct Update {
    pub workspace: [u8; 32],
    pub revision: u64,
    pub topic: String,
    pub subscribed: bool,
}

struct Pending {
    update: Update,
    task: tokio::task::JoinHandle<Result<AdmissionReport, arachne_node::Error>>,
}
impl Drop for Pending {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[derive(Default)]
pub(super) struct Updates {
    pending: Option<Pending>,
    queued: VecDeque<Update>,
    desired: BTreeMap<([u8; 32], String), Update>,
    repair: VecDeque<Update>,
    retry_at: Option<Instant>,
}

impl Updates {
    pub fn is_idle(&self) -> bool {
        self.pending.is_none() && self.queued.is_empty() && self.repair.is_empty()
    }
    pub fn set(&mut self, node: &Node, runtime: &Runtime, update: Update) -> Result<Value, String> {
        let key = (update.workspace, update.topic.clone());
        let existing = self
            .queued
            .iter()
            .position(|old| old.workspace == update.workspace && old.topic == update.topic);
        if existing.is_none() && self.queued.len() >= MAX_INTERESTS {
            return Err("interest update queue is full".into());
        }
        if !self.desired.contains_key(&key) && self.desired.len() >= MAX_INTERESTS {
            return Err("desired interest set is full".into());
        }
        let sending = runtime
            .block_on(node.prepare_interest(
                update.workspace,
                update.revision,
                Topic::new(update.topic.clone()).map_err(|e| e.to_string())?,
                update.subscribed,
            ))
            .map_err(|e| e.to_string())?;
        self.desired.insert(key.clone(), update.clone());
        self.repair
            .retain(|old| (old.workspace, old.topic.clone()) != key);
        // Desired local interest already changed. Coalesce queued changes without
        // moving their FIFO position or spawning a task per topic/member.
        if self.is_idle() {
            self.pending = Some(Pending {
                update,
                task: runtime.spawn(sending),
            });
        } else if let Some(position) = existing {
            self.queued[position] = update;
        } else {
            self.queued.push_back(update);
        }
        Ok(json!({"state":"interest_queued", "queued":self.queued.len()}))
    }

    /// Replay the bounded desired set after a transport or peer lifecycle change.
    /// Explicit queued changes retain precedence over a repair snapshot.
    pub fn repair(&mut self) {
        self.repair = self
            .desired
            .values()
            .filter(|update| {
                // An in-flight announcement can precede the peer's restart.
                // Replay it too; queued changes have not been sent yet.
                !self.queued.iter().any(|queued| {
                    queued.workspace == update.workspace && queued.topic == update.topic
                })
            })
            .cloned()
            .collect();
    }

    pub fn replace_revision(&mut self, workspace: [u8; 32], revision: u64) {
        self.desired
            .retain(|(scope, _), update| *scope != workspace || update.revision == revision);
        self.queued
            .retain(|update| update.workspace != workspace || update.revision == revision);
        self.repair
            .retain(|update| update.workspace != workspace || update.revision == revision);
        if self.pending.as_ref().is_some_and(|pending| {
            pending.update.workspace == workspace && pending.update.revision != revision
        }) {
            self.pending = None;
        }
    }

    pub fn poll(&mut self, node: &Node, runtime: &Runtime) -> Value {
        if self.is_idle() && self.retry_at.is_some_and(|at| Instant::now() >= at) {
            self.retry_at = None;
            self.repair();
        }
        let result = if self
            .pending
            .as_ref()
            .is_some_and(|job| job.task.is_finished())
        {
            let mut job = self.pending.take().unwrap();
            let mut value = json!({"state":"interest_observed", "workspace":job.update.workspace,
                "revision":job.update.revision, "topic":job.update.topic, "subscribed":job.update.subscribed});
            match runtime.block_on(&mut job.task) {
                Ok(Ok(outcome)) => {
                    if !outcome.failed.is_empty() {
                        self.retry_at = Some(Instant::now() + RETRY_DELAY);
                    }
                    let withdrawal_observed = !job.update.subscribed && outcome.failed.is_empty();
                    value["admission"] = report(outcome);
                    if withdrawal_observed
                        && self
                            .desired
                            .get(&(job.update.workspace, job.update.topic.clone()))
                            .is_some_and(|desired| {
                                !desired.subscribed && desired.revision == job.update.revision
                            })
                    {
                        self.desired
                            .remove(&(job.update.workspace, job.update.topic.clone()));
                    }
                }
                other => {
                    self.retry_at = Some(Instant::now() + RETRY_DELAY);
                    value["state"] = json!("interest_failed");
                    value["error"] = json!(format!("{other:?}"));
                }
            }
            value
        } else {
            Value::Null
        };
        if self.pending.is_none()
            && let Some(update) = self.queued.pop_front().or_else(|| self.repair.pop_front())
        {
            // Revalidate against current policy. A queued old revision must not
            // restore authority after membership replacement.
            match runtime.block_on(node.prepare_interest(
                update.workspace,
                update.revision,
                Topic::new(update.topic.clone()).expect("queued topic was validated"),
                update.subscribed,
            )) {
                Ok(sending) => {
                    self.pending = Some(Pending {
                        update,
                        task: runtime.spawn(sending),
                    })
                }
                Err(error) => return json!({"state":"interest_failed", "error":error.to_string()}),
            }
        }
        if result.is_null() && self.pending.is_some() {
            json!({"state":"interest_pending", "queued":self.queued.len()})
        } else {
            result
        }
    }

    pub fn cancel(&mut self) {
        self.pending = None;
        self.queued.clear();
        self.desired.clear();
        self.repair.clear();
        self.retry_at = None;
    }
}
