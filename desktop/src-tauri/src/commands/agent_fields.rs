use buzz_core_pkg::agent_field::{current_fields, validate_envelope, FieldType, Visibility};
use nostr::{Event, Keys, PublicKey};
use serde::Serialize;
use tauri::State;

use crate::app_state::AppState;

/// One readable NIP-AF field as shown in the agent profile.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentFieldView {
    key: String,
    value: String,
    #[serde(rename = "type")]
    field_type: FieldType,
    visibility: Visibility,
    created_at: u64,
}

/// Decode an agent's kind:30173 events into the fields the signed-in user can
/// read: the newest event per `d` tag, then the newest readable value per key.
/// Events that are unsigned, unreadable, unsupported, or tombstones are
/// skipped (NIP-AF forward compatibility).
#[tauri::command]
pub async fn read_agent_fields(
    agent_pubkey: String,
    events: Vec<serde_json::Value>,
    state: State<'_, AppState>,
) -> Result<Vec<AgentFieldView>, String> {
    let keys = state.signing_keys()?;
    let agent = PublicKey::from_hex(agent_pubkey.trim())
        .map_err(|error| format!("invalid agent pubkey: {error}"))?;
    tauri::async_runtime::spawn_blocking(move || {
        let events = events
            .into_iter()
            .filter_map(|value| serde_json::from_value::<Event>(value).ok());
        readable_field_heads(&keys, &agent, events)
    })
    .await
    .map_err(|e| format!("spawn_blocking failed: {e}"))
}

fn readable_field_heads(
    reader: &Keys,
    agent: &PublicKey,
    events: impl IntoIterator<Item = Event>,
) -> Vec<AgentFieldView> {
    let events: Vec<Event> = events.into_iter().collect();
    let reader_hex = reader.public_key().to_hex();
    let owns_agent = events.iter().any(|event| {
        event.pubkey == *agent
            && validate_envelope(event).is_ok_and(|e| e.owner == Some(reader_hex.as_str()))
    });
    let owner_keys = owns_agent.then(|| (reader.secret_key(), agent));
    current_fields(agent, events, owner_keys)
        .into_iter()
        .filter_map(|field| {
            Some(AgentFieldView {
                value: field.body.value?,
                key: field.body.key,
                field_type: field.body.field_type,
                visibility: field.body.visibility,
                created_at: field.created_at,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use buzz_core_pkg::agent_field::{build_event, conversation_key, d_tag, FieldBody};
    use buzz_core_pkg::kind::KIND_AGENT_FIELD;
    use nostr::{EventBuilder, Kind, Tag};

    fn field(key: &str, value: Option<&str>, visibility: Visibility) -> FieldBody {
        FieldBody {
            key: key.into(),
            value: value.map(Into::into),
            field_type: FieldType::Text,
            visibility,
        }
    }

    fn keys_seen(reader: &Keys, agent: &Keys, events: &[Event]) -> Vec<(String, String)> {
        readable_field_heads(reader, &agent.public_key(), events.to_vec())
            .into_iter()
            .map(|f| (f.key, f.value))
            .collect()
    }

    #[test]
    fn agent_field_heads_respect_reader_and_skip_unknown() {
        let agent = Keys::generate();
        let owner = Keys::generate();
        let stranger = Keys::generate();
        let op = owner.public_key();
        let build = |body: FieldBody, at: u64| build_event(&agent, &op, &body, at).unwrap();

        let k_c = conversation_key(agent.secret_key(), &op);
        let future_visibility = EventBuilder::new(
            Kind::Custom(KIND_AGENT_FIELD as u16),
            r#"{"key":"focus","value":"x","type":"text","visibility":"channel"}"#,
        )
        .tags([Tag::parse(["d", &d_tag(&k_c, "focus")]).unwrap()])
        .sign_with_keys(&agent)
        .unwrap();

        let events = vec![
            build(field("cost", Some("0.10"), Visibility::Owner), 1),
            build(field("cost", Some("0.41"), Visibility::Owner), 2),
            build(field("model", Some("opus"), Visibility::Community), 1),
            build(field("thinking", Some("high"), Visibility::Community), 1),
            build(field("thinking", None, Visibility::Owner), 2),
            future_visibility,
        ];

        assert_eq!(
            keys_seen(&owner, &agent, &events),
            [
                ("cost".into(), "0.41".into()),
                ("model".into(), "opus".into())
            ]
        );
        assert_eq!(
            keys_seen(&stranger, &agent, &events),
            [("model".into(), "opus".into())]
        );
    }
}
