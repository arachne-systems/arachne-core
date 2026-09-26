//! `next_event`: one typed pull over every queue of a session (ADR step 4).
//!
//! While no candidate or inbound exchange blocks the session, control
//! requests and deliveries report until the host drains them with their
//! poll call. Everything else reports once: a ready job (recovery range,
//! current view, interest, presence), membership gossip, an admission queue
//! the runtime may not stage yet, and queues that a pending candidate
//! blocks. A job reports again after its ready state was cleared; a
//! blocked queue reports again after the host runs an op. So a host that
//! waits, drains and waits again never spins.

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

/// Kinds already reported that are still ready.
#[derive(Default)]
pub(crate) struct Reported(BTreeSet<Kind>);

impl Reported {
    /// An op ran: queues that a candidate blocked may be served now.
    pub(crate) fn rearm_queues(&mut self) {
        self.0
            .retain(|kind| !matches!(kind, Kind::Control | Kind::Membership | Kind::Deliveries));
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Kind {
    Control,
    Membership,
    Deliveries,
    Recovery,
    CurrentView,
    Interest,
    Presence,
}

/// What a session has now. Cheap checks only; nothing is consumed.
#[derive(Clone, Copy, Debug, Default)]
struct Probe {
    /// A candidate or inbound exchange waits: some polls serve nothing.
    busy: bool,
    controls: bool,
    /// Admissions the runtime queued for a later staging pass.
    admissions: bool,
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
    let recovery = &session.recovery;
    Probe {
        busy: crate::ops::admission_busy(session),
        controls: session.node.has_queued_controls() || session.node.has_deferred_controls(),
        admissions: !session.admission.queue.is_empty(),
        membership: session.node.has_membership_gossip()
            || crate::membership::fork::has_carried_work(session)
            || crate::membership::fork::has_republication_work(session)
            || crate::membership::fork::has_retry_work(session)
            || session.membership.fork.has_result()
            || session.membership.update.as_ref().is_some_and(|job| job.task.is_finished())
            || session.membership.offer.as_ref().is_some_and(|job| job.task.is_finished())
            || session.membership.range_pull.as_ref().is_some_and(|job| job.task.is_finished())
            || session.membership.profile_pull.as_ref().is_some_and(|job| job.task.is_finished()),
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
        interest: session.interests.has_result() || session.interests.has_work_to_start(),
        presence: session.presence.has_result(),
        in_flight: recovery.range.is_some()
            || recovery.direct_range.is_some()
            || recovery.current_view.is_some()
            || session.interests.is_running()
            || session.presence.in_flight_count() != 0
            || session.membership.fork.is_running()
            || session.membership.update.is_some()
            || session.membership.offer.is_some()
            || session.membership.range_pull.is_some()
            || session.membership.profile_pull.is_some(),
    }
}

fn delivery_event(probe: &Probe) -> Event {
    if probe.workspace {
        Event::ProtectedReceived
    } else {
        Event::PublicationReceived
    }
}

/// The first event of `probe`, in a fixed order: control first, because an
/// unserved control request holds a peer.
fn classify(probe: Probe, reported: &mut Reported) -> Option<Event> {
    if !probe.busy {
        if probe.controls {
            reported.0.remove(&Kind::Control);
            return Some(Event::Control);
        }
        if probe.deliveries {
            reported.0.remove(&Kind::Deliveries);
            return Some(delivery_event(&probe));
        }
    }
    let once = [
        (
            Kind::Control,
            probe.controls || (!probe.busy && probe.admissions),
            Event::Control,
        ),
        (Kind::Membership, probe.membership, Event::MembershipChanged),
        (Kind::Deliveries, probe.deliveries, delivery_event(&probe)),
        (Kind::Recovery, probe.recovery, Event::RecoveryReady),
        (Kind::CurrentView, probe.current_view, Event::CurrentViewReady),
        (Kind::Interest, probe.interest, Event::InterestChanged),
        (Kind::Presence, probe.presence, Event::Presence),
    ];
    let mut found = None;
    for (kind, ready, event) in once {
        if !ready {
            reported.0.remove(&kind);
        } else if found.is_none() && reported.0.insert(kind) {
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
            (Probe { admissions: true, ..Probe::default() }, Event::Control),
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
    fn a_blocked_queue_reports_once_until_an_op_runs() {
        let mut reported = Reported::default();
        // A pending candidate: control and deliveries may not drain.
        let blocked = Probe { busy: true, controls: true, deliveries: true, ..Probe::default() };
        assert_eq!(classify(blocked, &mut reported), Some(Event::Control));
        assert_eq!(classify(blocked, &mut reported), Some(Event::PublicationReceived));
        assert_eq!(classify(blocked, &mut reported), None);
        reported.rearm_queues();
        assert_eq!(classify(blocked, &mut reported), Some(Event::Control));
        // Queued admissions the runtime holds report once, even when not busy.
        let mut reported = Reported::default();
        let held = Probe { admissions: true, ..Probe::default() };
        assert_eq!(classify(held, &mut reported), Some(Event::Control));
        assert_eq!(classify(held, &mut reported), None);
        // Membership gossip reports once.
        let gossip = Probe { membership: true, ..Probe::default() };
        assert_eq!(classify(gossip, &mut reported), Some(Event::MembershipChanged));
        assert_eq!(classify(gossip, &mut reported), None);
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
