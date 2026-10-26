//! `buzz agents fields` — agent-side NIP-AF field management.
//!
//! Owner resolution, event parsing and LWW conflict reporting are shared
//! with `buzz mem` (NIP-AE), which uses the same agent↔owner key pair.

use std::collections::HashMap;

use buzz_core::agent_field::{
    self, conversation_key, d_tag, read_event, validate_envelope, FieldBody, FieldType, Visibility,
};
use buzz_core::engram::{monotonic_created_at, select_head};
use buzz_core::kind::KIND_AGENT_FIELD;
use nostr::{Event, PublicKey, SecretKey};
use serde::Serialize;

use crate::client::{normalize_write_response, BuzzClient};
use crate::commands::mem::{now_secs, parse_events, resolve_owner, submit_engram};
use crate::error::CliError;
use crate::validate::read_or_stdin;
use crate::{FieldTypeArg, FieldVisibilityArg, FieldsCmd};

/// One current field in `buzz agents fields list` output.
#[derive(Debug, Serialize, PartialEq)]
struct Listing {
    key: String,
    value: String,
    #[serde(rename = "type")]
    field_type: FieldType,
    visibility: Visibility,
    created_at: u64,
}

/// Decode `events` and keep the newest valid event per key, dropping
/// tombstones. `keys` is `(my_seckey, their_pubkey)` for the agent or its
/// owner; `None` reads community fields only.
fn current_fields(events: Vec<Event>, keys: Option<(&SecretKey, &PublicKey)>) -> Vec<Listing> {
    let mut by_key: HashMap<String, Vec<(Event, FieldBody)>> = HashMap::new();
    for event in events {
        if event.verify().is_err() {
            continue;
        }
        if let Ok(body) = read_event(&event, keys) {
            by_key
                .entry(body.key.clone())
                .or_default()
                .push((event, body));
        }
    }
    let mut listings: Vec<Listing> = by_key
        .into_values()
        .filter_map(|members| {
            let head = select_head(members.iter().map(|(e, _)| e.clone()))?;
            let (event, body) = members.into_iter().find(|(e, _)| e.id == head.id)?;
            Some(Listing {
                value: body.value?,
                key: body.key,
                field_type: body.field_type,
                visibility: body.visibility,
                created_at: event.created_at.as_secs(),
            })
        })
        .collect();
    listings.sort_by(|a, b| a.key.cmp(&b.key));
    listings
}

async fn query_fields(
    client: &BuzzClient,
    agent: &PublicKey,
    d: Option<&str>,
) -> Result<Vec<Event>, CliError> {
    let mut filter = serde_json::json!({
        "kinds": [KIND_AGENT_FIELD],
        "authors": [agent.to_hex()],
        "limit": 1000,
    });
    if let Some(d) = d {
        filter["#d"] = serde_json::json!([d]);
    }
    parse_events(&client.query(&filter).await?)
}

/// Publish `value` (or a tombstone when `None`) for `key` as this agent.
async fn write(
    client: &BuzzClient,
    key: &str,
    value: Option<String>,
    field_type: FieldType,
    visibility: Visibility,
    owner_flag: Option<&str>,
) -> Result<(), CliError> {
    agent_field::validate_key(key).map_err(|e| CliError::Usage(e.to_string()))?;
    let owner = resolve_owner(client, owner_flag)?;
    let keys = client.keys();
    let d = d_tag(&conversation_key(keys.secret_key(), &owner), key);
    let prior = query_fields(client, &keys.public_key(), Some(&d))
        .await?
        .into_iter()
        .filter(|e| e.verify().is_ok() && read_event(e, Some((keys.secret_key(), &owner))).is_ok());
    let created_at = monotonic_created_at(
        now_secs(),
        select_head(prior).map(|e| e.created_at.as_secs()),
    );
    let body = FieldBody {
        key: key.to_string(),
        value,
        field_type,
        visibility,
    };
    let event = agent_field::build_event(keys, &owner, &body, created_at)
        .map_err(|e| CliError::Usage(e.to_string()))?;
    let raw = submit_engram(client, event).await.map_err(|e| match e {
        CliError::Relay { status, body } if body.contains("unknown event kind") => {
            CliError::Relay {
                status,
                body: format!("agent fields are unsupported by this relay: {body}"),
            }
        }
        e => e,
    })?;
    println!("{}", normalize_write_response(&raw));
    Ok(())
}

async fn list(
    client: &BuzzClient,
    agent_flag: Option<&str>,
    owner_flag: Option<&str>,
) -> Result<(), CliError> {
    let me = client.keys();
    let agent = match agent_flag {
        Some(hex) => PublicKey::from_hex(hex)
            .map_err(|e| CliError::Usage(format!("--agent must be a 64-hex pubkey: {e}")))?,
        None => me.public_key(),
    };
    let events = query_fields(client, &agent, None).await?;
    let their_pubkey = if agent == me.public_key() {
        Some(resolve_owner(client, owner_flag)?)
    } else {
        // The relay accepts a `p` tag only for the author's registered owner,
        // so an event encrypted to us proves we own this agent.
        let my_hex = me.public_key().to_hex();
        events
            .iter()
            .any(|e| validate_envelope(e).is_ok_and(|env| env.owner == Some(my_hex.as_str())))
            .then_some(agent)
    };
    let listings = current_fields(
        events,
        their_pubkey.as_ref().map(|pk| (me.secret_key(), pk)),
    );
    let out = serde_json::to_string(&listings)
        .map_err(|e| CliError::Other(format!("failed to serialize fields: {e}")))?;
    println!("{out}");
    Ok(())
}

pub async fn dispatch(cmd: FieldsCmd, client: &BuzzClient) -> Result<(), CliError> {
    match cmd {
        FieldsCmd::Set {
            key,
            value,
            visibility,
            field_type,
            owner,
        } => {
            let visibility = match visibility {
                FieldVisibilityArg::Owner => Visibility::Owner,
                FieldVisibilityArg::Community => Visibility::Community,
            };
            let field_type = match field_type {
                FieldTypeArg::Text => FieldType::Text,
                FieldTypeArg::Transcript => FieldType::Transcript,
            };
            let value = read_or_stdin(&value)?;
            write(
                client,
                &key,
                Some(value),
                field_type,
                visibility,
                owner.as_deref(),
            )
            .await
        }
        FieldsCmd::Unset { key, owner } => {
            write(
                client,
                &key,
                None,
                FieldType::Text,
                Visibility::Owner,
                owner.as_deref(),
            )
            .await
        }
        FieldsCmd::List { agent, owner } => list(client, agent.as_deref(), owner.as_deref()).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::Keys;

    fn field(
        agent: &Keys,
        owner: &PublicKey,
        key: &str,
        value: Option<&str>,
        visibility: Visibility,
        at: u64,
    ) -> Event {
        let body = FieldBody {
            key: key.into(),
            value: value.map(Into::into),
            field_type: FieldType::Text,
            visibility,
        };
        agent_field::build_event(agent, owner, &body, at).unwrap()
    }

    #[test]
    fn list_keeps_newest_per_key_and_hides_owner_fields_from_others() {
        let agent = Keys::generate();
        let owner = Keys::generate();
        let o = owner.public_key();
        let events = vec![
            // Visibility change replaces the same key: newest wins.
            field(&agent, &o, "model", Some("old"), Visibility::Owner, 10),
            field(&agent, &o, "model", Some("new"), Visibility::Community, 11),
            field(&agent, &o, "cost", Some("0.1"), Visibility::Owner, 10),
            field(&agent, &o, "focus", Some("x"), Visibility::Community, 10),
            field(&agent, &o, "focus", None, Visibility::Community, 12),
        ];
        let pairs = |ls: Vec<Listing>| -> Vec<(String, String)> {
            ls.into_iter().map(|l| (l.key, l.value)).collect()
        };
        let expected_owner = vec![
            ("cost".to_string(), "0.1".to_string()),
            ("model".to_string(), "new".to_string()),
        ];
        let as_owner = current_fields(
            events.clone(),
            Some((owner.secret_key(), &agent.public_key())),
        );
        assert_eq!(pairs(as_owner), expected_owner);
        let as_agent = current_fields(events.clone(), Some((agent.secret_key(), &o)));
        assert_eq!(pairs(as_agent), expected_owner);
        let as_member = current_fields(events, None);
        assert_eq!(
            pairs(as_member),
            vec![
                ("focus".to_string(), "x".to_string()),
                ("model".to_string(), "new".to_string()),
            ]
        );
    }
}
