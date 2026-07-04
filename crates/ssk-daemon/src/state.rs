#![forbid(unsafe_code)]

use ssk_ipc::{DaemonState, Event};
use tokio::sync::broadcast;

/// Owns the daemon's single authoritative state and the event bus that
/// notifies subscribers of every transition
/// (`docs/DESKTOP_CLIENT_ARCHITECTURE.md` sections K.1/K.3). The GUI/CLI
/// render this state; they never infer it independently.
pub struct StateMachine {
    current: DaemonState,
    events: broadcast::Sender<Event>,
}

impl StateMachine {
    #[must_use]
    pub fn new(event_capacity: usize) -> Self {
        let (events, _rx) = broadcast::channel(event_capacity);
        Self {
            current: DaemonState::Inactive,
            events,
        }
    }

    #[must_use]
    pub fn current(&self) -> DaemonState {
        self.current
    }

    /// Move to `to`, recording `reason` and notifying subscribers.
    pub fn transition(&mut self, to: DaemonState, reason: impl Into<String>) {
        let from = self.current;
        self.current = to;
        let _ = self.events.send(Event::StateChanged {
            from,
            to,
            reason: reason.into(),
        });
    }

    /// Publish an event that is not itself a state transition (e.g. an audit
    /// append or a health warning).
    pub fn emit(&self, event: Event) {
        let _ = self.events.send(event);
    }

    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.events.subscribe()
    }
}

impl Default for StateMachine {
    fn default() -> Self {
        Self::new(256)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_inactive() {
        let sm = StateMachine::default();
        assert_eq!(sm.current(), DaemonState::Inactive);
    }

    #[tokio::test]
    async fn transition_emits_state_changed_event() {
        let mut sm = StateMachine::default();
        let mut rx = sm.subscribe();
        sm.transition(DaemonState::Activating, "activate_profile called");
        let event = rx.recv().await.expect("event");
        match event {
            Event::StateChanged { from, to, reason } => {
                assert_eq!(from, DaemonState::Inactive);
                assert_eq!(to, DaemonState::Activating);
                assert_eq!(reason, "activate_profile called");
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[tokio::test]
    async fn lagging_subscriber_observes_lagged_not_a_hang() {
        let sm = StateMachine::new(2);
        let mut rx = sm.subscribe();
        // Publish more events than the bounded channel can hold without the
        // subscriber reading, forcing a `RecvError::Lagged`.
        for i in 0..10u64 {
            sm.emit(Event::AuditAppended {
                seq: i,
                entry_hash: format!("hash-{i}"),
            });
        }
        let err = rx.recv().await.expect_err("receiver must have lagged");
        assert!(matches!(err, broadcast::error::RecvError::Lagged(_)));
    }
}
