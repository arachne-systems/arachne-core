//! `next_event`: one typed pull over every queue of a session (ADR step 4).
//!
//! Queues (control requests, deliveries, membership gossip) report while
//! they are not empty: the host drains them with their poll call. A ready
//! job (recovery range, current view, interest, presence) reports once; it
//! reports again only after its ready state was cleared. So a host that
//! drains and calls again never spins on one ready job.

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use arachne_api::{ApiError, Event};

use crate::Session;
use crate::errors;
use crate::registry;
use crate::work_signal::Wake;

/// How often a waiter looks again while a background job is in flight:
/// job tasks do not raise the work signal when they end.
const JOB_TICK: Duration = Duration::from_millis(100);

/// Job kinds already reported and still ready.
#[derive(Default)]
pub(crate) struct Reported(BTreeSet<Job>);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Job {
    Recovery,
    CurrentView,
    Interest,
    Presence,
}

/// What a session has now. Cheap checks only; nothing is consumed.
#[derive(Clone, Copy, Debug, Default)]
struct Probe {
    controls: bool,
    membership: bool,
    deliveries: bool,
    workspace: bool,
    recovery: bool,
    current_view: bool,
    interest: bool,
    presence: bool,
    /// A background job runs and may end without a raise.
    in_flight: bool,
}

fn probe(session: &Session) -> Probe {
    let busy = crate::ops::admission_busy(session);
    let recovery = &session.recovery;
    Probe {
        controls: session.node.has_queued_controls()
            || (!busy && (session.node.has_deferred_controls() || !session.admission.queue.is_empty())),
        membership: session.node.has_membership_gossip(),
        deliveries: !session.receiver.is_empty(),
        workspace: session.workspace.is_some(),
        recovery: recovery.ready_range.is_some()
            || recovery.ready_direct_range.is_some()
            || recovery.range.as_ref().is_some_and(|job| job.task.is_finished())
            || recovery
                .direct_range
                .as_ref()
                .is_some_and(|job| job.task.is_finished()),
        current_view: recovery.ready_current_view.is_some()
            || recovery
                .current_view
                .as_ref()
                .is_some_and(|job| job.task.is_finished()),
        interest: session.interests.has_result(),
        presence: session.presence.has_result(),
        in_flight: recovery.range.is_some()
            || recovery.direct_range.is_some()
            || recovery.current_view.is_some()
            || !session.interests.is_idle()
            || session.presence.in_flight_count() != 0,
    }
}

/// The first event of `probe`, in a fixed order: control first, because an
/// unserved control request holds a peer.
fn classify(probe: Probe, reported: &mut Reported) -> Option<Event> {
    if probe.controls {
        return Some(Event::Control);
    }
    if probe.membership {
        return Some(Event::MembershipChanged);
    }
    if probe.deliveries {
        return Some(if probe.workspace {
            Event::ProtectedReceived
        } else {
            Event::PublicationReceived
        });
    }
    let jobs = [
        (Job::Recovery, probe.recovery, Event::RecoveryReady),
        (Job::CurrentView, probe.current_view, Event::CurrentViewReady),
        (Job::Interest, probe.interest, Event::InterestChanged),
        (Job::Presence, probe.presence, Event::Presence),
    ];
    let mut found = None;
    for (job, ready, event) in jobs {
        if !ready {
            reported.0.remove(&job);
        } else if found.is_none() && reported.0.insert(job) {
            found = Some(event);
        }
    }
    found
}

/// Wait up to `timeout` (`None`: no timeout) for the next event.
/// `Ok(None)`: the timeout passed, `wake` was called, or the session closed
/// while it waited. `Event::Closed`: the runtime ended the session (for
/// example a removal); the host still calls `close`.
pub(crate) fn next(handle: i64, timeout: Option<Duration>) -> Result<Option<Event>, ApiError> {
    let entry = registry::entry(handle)?;
    let deadline = timeout.map(|timeout| Instant::now() + timeout);
    loop {
        let (event, in_flight) = {
            let mut guard = entry
                .shared
                .lock()
                .map_err(errors::poisoned("node session unavailable"))?;
            match guard.as_mut() {
                None if entry.signal.is_closed() => return Ok(None),
                None => return Ok(Some(Event::Closed)),
                Some(session) => {
                    let probe = probe(session);
                    (classify(probe, &mut session.events), probe.in_flight)
                }
            }
        };
        if event.is_some() {
            return Ok(event);
        }
        let remaining =
            deadline.map(|deadline| deadline.saturating_duration_since(Instant::now()));
        if remaining == Some(Duration::ZERO) {
            return Ok(None);
        }
        let slice = match (remaining, in_flight) {
            (Some(remaining), true) => Some(remaining.min(JOB_TICK)),
            (None, true) => Some(JOB_TICK),
            (remaining, false) => remaining,
        };
        match entry.signal.wait_for(slice) {
            Wake::Closed | Wake::Woken => return Ok(None),
            Wake::Work | Wake::TimedOut => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(probe: Probe) -> Option<Event> {
        classify(probe, &mut Reported::default())
    }

    #[test]
    fn each_queue_and_job_has_its_event() {
        let cases = [
            (Probe { controls: true, ..Probe::default() }, Event::Control),
            (Probe { membership: true, ..Probe::default() }, Event::MembershipChanged),
            (Probe { deliveries: true, ..Probe::default() }, Event::PublicationReceived),
            (
                Probe { deliveries: true, workspace: true, ..Probe::default() },
                Event::ProtectedReceived,
            ),
            (Probe { recovery: true, ..Probe::default() }, Event::RecoveryReady),
            (Probe { current_view: true, ..Probe::default() }, Event::CurrentViewReady),
            (Probe { interest: true, ..Probe::default() }, Event::InterestChanged),
            (Probe { presence: true, ..Probe::default() }, Event::Presence),
        ];
        for (probe, event) in cases {
            assert_eq!(one(probe), Some(event.clone()), "{probe:?}");
        }
        assert_eq!(one(Probe::default()), None);
        assert_eq!(one(Probe { in_flight: true, ..Probe::default() }), None);
    }

    #[test]
    fn queues_repeat_until_drained_and_jobs_report_once() {
        let mut reported = Reported::default();
        let queue = Probe { deliveries: true, ..Probe::default() };
        assert_eq!(classify(queue, &mut reported), Some(Event::PublicationReceived));
        assert_eq!(classify(queue, &mut reported), Some(Event::PublicationReceived));

        let both = Probe { recovery: true, presence: true, ..Probe::default() };
        assert_eq!(classify(both, &mut reported), Some(Event::RecoveryReady));
        assert_eq!(classify(both, &mut reported), Some(Event::Presence));
        assert_eq!(classify(both, &mut reported), None);
        // Cleared, then ready again: a new job reports again.
        assert_eq!(classify(Probe::default(), &mut reported), None);
        assert_eq!(classify(both, &mut reported), Some(Event::RecoveryReady));
    }

    #[test]
    fn control_comes_before_every_other_kind() {
        let all = Probe {
            controls: true,
            membership: true,
            deliveries: true,
            recovery: true,
            interest: true,
            ..Probe::default()
        };
        assert_eq!(one(all), Some(Event::Control));
    }
}
