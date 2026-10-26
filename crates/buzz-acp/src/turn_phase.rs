//! Coarse, public "what is the agent doing" phase for one in-flight turn.
//!
//! The ACP read loop writes the phase as `session/update` notifications
//! arrive; the main loop reads it when it publishes typing indicators. Only
//! the phase crosses to the relay, never tool names or content: typing events
//! are visible to everyone in the channel.

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

/// What the agent is doing right now, as advertised in the typing `phase` tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TurnPhase {
    /// Model reasoning, or waiting on the model between tool calls.
    Thinking,
    /// A tool call is running.
    Tool,
    /// Streaming its reply.
    Writing,
}

impl TurnPhase {
    /// Wire value of the typing event's `phase` tag.
    pub fn as_tag_value(self) -> &'static str {
        match self {
            Self::Thinking => "thinking",
            Self::Tool => "tool",
            Self::Writing => "writing",
        }
    }

    /// Phase implied by an ACP `session/update` payload, if any.
    pub fn from_session_update(update: &serde_json::Value) -> Option<Self> {
        match update.get("sessionUpdate")?.as_str()? {
            "agent_thought_chunk" => Some(Self::Thinking),
            "agent_message_chunk" => Some(Self::Writing),
            "tool_call" => Some(Self::Tool),
            "tool_call_update" => match update.get("status").and_then(|s| s.as_str()) {
                Some("completed" | "failed") => Some(Self::Thinking),
                _ => Some(Self::Tool),
            },
            _ => None,
        }
    }
}

/// Shared phase of one turn. Unset until the agent's first phase-bearing update.
#[derive(Clone, Debug, Default)]
pub struct PhaseCell(Arc<AtomicU8>);

impl PhaseCell {
    /// Record the turn's current phase.
    pub fn set(&self, phase: TurnPhase) {
        let raw = match phase {
            TurnPhase::Thinking => 1,
            TurnPhase::Tool => 2,
            TurnPhase::Writing => 3,
        };
        self.0.store(raw, Ordering::Relaxed);
    }

    /// The turn's current phase, if the agent has reported one.
    pub fn get(&self) -> Option<TurnPhase> {
        match self.0.load(Ordering::Relaxed) {
            1 => Some(TurnPhase::Thinking),
            2 => Some(TurnPhase::Tool),
            3 => Some(TurnPhase::Writing),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn session_updates_map_to_phases() {
        let cases = [
            (
                json!({"sessionUpdate": "agent_thought_chunk"}),
                Some(TurnPhase::Thinking),
            ),
            (
                json!({"sessionUpdate": "agent_message_chunk"}),
                Some(TurnPhase::Writing),
            ),
            (json!({"sessionUpdate": "tool_call"}), Some(TurnPhase::Tool)),
            (
                json!({"sessionUpdate": "tool_call_update", "status": "in_progress"}),
                Some(TurnPhase::Tool),
            ),
            (
                json!({"sessionUpdate": "tool_call_update", "status": "completed"}),
                Some(TurnPhase::Thinking),
            ),
            (
                json!({"sessionUpdate": "tool_call_update", "status": "failed"}),
                Some(TurnPhase::Thinking),
            ),
            (json!({"sessionUpdate": "usage_update"}), None),
            (json!({}), None),
        ];
        for (update, expected) in cases {
            assert_eq!(
                TurnPhase::from_session_update(&update),
                expected,
                "{update}"
            );
        }
    }

    #[test]
    fn cell_is_unset_until_written_and_shared_across_clones() {
        let cell = PhaseCell::default();
        let reader = cell.clone();
        assert_eq!(reader.get(), None);
        cell.set(TurnPhase::Tool);
        assert_eq!(reader.get(), Some(TurnPhase::Tool));
    }
}
