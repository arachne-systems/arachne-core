use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// Durable lifecycle phases projected to every adapter.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Empty,
    Creating,
    Joining,
    Synchronizing,
    Active,
    Recovering,
    Leaving,
    Resetting,
    Removed,
    Failed,
}

/// The one restart-safe workspace lifecycle value. Membership and delivery
/// details remain separate projections; this value only answers where the
/// workspace operation is and why it stopped.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Activity {
    pub phase: Phase,
    pub reason: Option<String>,
}

impl Default for Activity {
    fn default() -> Self {
        Self {
            phase: Phase::Empty,
            reason: None,
        }
    }
}

impl Activity {
    pub(super) fn transition(&mut self, next: Phase, reason: Option<&str>) -> Result<(), String> {
        if self.phase != next && !legal(self.phase, next) {
            return Err(format!(
                "invalid workspace activity transition: {:?} -> {:?}",
                self.phase, next
            ));
        }
        let reason = reason.map(str::to_owned);
        if let Some(value) = &reason
            && (value.is_empty()
                || value.len() > 64
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'))
        {
            return Err("workspace activity reason is not a stable code".into());
        }
        self.reason = reason;
        self.phase = next;
        Ok(())
    }

    pub(super) fn projection(&self) -> Value {
        json!({"state": self.phase, "reason": self.reason})
    }
}

fn legal(from: Phase, to: Phase) -> bool {
    matches!(
        (from, to),
        (
            Phase::Empty,
            Phase::Creating | Phase::Joining | Phase::Active | Phase::Resetting | Phase::Failed
        ) | (
            Phase::Creating,
            Phase::Active | Phase::Failed | Phase::Resetting
        ) | (
            Phase::Joining,
            Phase::Synchronizing | Phase::Failed | Phase::Resetting
        ) | (
            Phase::Synchronizing,
            Phase::Active | Phase::Recovering | Phase::Failed | Phase::Resetting
        ) | (
            Phase::Active,
            Phase::Recovering | Phase::Leaving | Phase::Resetting | Phase::Failed
        ) | (
            Phase::Recovering,
            Phase::Active | Phase::Failed | Phase::Resetting
        ) | (
            Phase::Leaving,
            Phase::Removed | Phase::Failed | Phase::Resetting
        ) | (Phase::Removed, Phase::Empty | Phase::Resetting)
            | (
                Phase::Failed,
                Phase::Empty
                    | Phase::Creating
                    | Phase::Joining
                    | Phase::Recovering
                    | Phase::Resetting
                    | Phase::Failed
            )
            | (Phase::Resetting, Phase::Empty | Phase::Failed)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legal_transitions_are_strict_and_idempotent() {
        let mut activity = Activity::default();
        activity.transition(Phase::Creating, None).unwrap();
        assert!(activity.transition(Phase::Active, None).is_ok());
        let snapshot = activity.clone();
        assert!(activity.transition(Phase::Joining, None).is_err());
        assert_eq!(activity, snapshot);
        activity
            .transition(Phase::Failed, Some("join_timeout"))
            .unwrap();
        activity
            .transition(Phase::Failed, Some("join_timeout"))
            .unwrap();
        assert_eq!(activity.projection()["state"], json!("failed"));
        assert_eq!(activity.projection()["reason"], json!("join_timeout"));
    }
}
