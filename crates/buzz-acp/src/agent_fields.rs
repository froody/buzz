//! NIP-AF harness-written agent fields (`docs/nips/NIP-AF.md`).
//!
//! At turn end the harness publishes its reserved owner-only fields
//! (`harness`, `model`, `thinking`, `context`, `cost`), skipping keys whose
//! value is unchanged since the last successful publish.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use buzz_core::agent_field::{self, keys, FieldBody, FieldType, Visibility};
use buzz_core::engram::monotonic_created_at;

use crate::relay::{RelayError, RestClient};
use crate::usage::TurnUsage;

const PUBLISH_TIMEOUT: Duration = Duration::from_secs(3);

/// Per-process publisher of the harness's reserved agent fields.
pub struct AgentFields {
    harness: String,
    configured_model: Option<String>,
    thinking: Option<String>,
    state: Mutex<PublishState>,
}

#[derive(Default)]
struct PublishState {
    published: HashMap<&'static str, String>,
    /// `created_at` of the last publish, so replacements are strictly newer.
    last_created_at: u64,
    /// Set once the relay rejects kind 30173 as unknown.
    disabled: bool,
}

impl AgentFields {
    /// Create a publisher from the harness identity and configured model/effort.
    pub fn new(
        harness: String,
        configured_model: Option<String>,
        thinking: Option<String>,
    ) -> Self {
        Self {
            harness,
            configured_model,
            thinking,
            state: Mutex::default(),
        }
    }

    /// Current field values derived from this turn's usage (if any).
    fn values(&self, usage: Option<&TurnUsage>) -> Vec<(&'static str, String)> {
        let model = usage
            .and_then(|u| u.model.clone())
            .or_else(|| self.configured_model.clone());
        let context = usage
            .and_then(|u| u.context_tokens)
            .map(|(used, limit)| format!("{used}/{limit}"));
        let cost = usage
            .and_then(|u| u.cumulative_cost_usd)
            .map(|c| format!("{c:.4}"));
        [
            (keys::HARNESS, Some(self.harness.clone())),
            (keys::MODEL, model),
            (keys::THINKING, self.thinking.clone()),
            (keys::CONTEXT, context),
            (keys::COST, cost),
        ]
        .into_iter()
        .filter_map(|(k, v)| Some((k, v?)))
        .collect()
    }

    /// Fields whose value differs from the last published one; empty once disabled.
    fn changed(&self, usage: Option<&TurnUsage>) -> Vec<(&'static str, String)> {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.disabled {
            return Vec::new();
        }
        self.values(usage)
            .into_iter()
            .filter(|(k, v)| state.published.get(k) != Some(v))
            .collect()
    }

    fn next_created_at(&self, now: u64) -> u64 {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.last_created_at = monotonic_created_at(now, Some(state.last_created_at));
        state.last_created_at
    }

    fn mark_published(&self, key: &'static str, value: String) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.published.insert(key, value);
    }

    fn disable(&self) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.disabled = true;
    }

    /// Publish changed fields in the background; never blocks the caller.
    pub fn publish(
        self: &Arc<Self>,
        rest_client: &RestClient,
        agent_keys: &nostr::Keys,
        owner: nostr::PublicKey,
        usage: Option<&TurnUsage>,
    ) {
        let changed = self.changed(usage);
        if changed.is_empty() {
            return;
        }
        let created_at = self.next_created_at(nostr::Timestamp::now().as_secs());
        let this = Arc::clone(self);
        let rest_client = rest_client.clone();
        let agent_keys = agent_keys.clone();
        tokio::spawn(async move {
            for (key, value) in changed {
                let body = FieldBody {
                    key: key.to_string(),
                    value: Some(value.clone()),
                    field_type: FieldType::Text,
                    visibility: Visibility::Owner,
                };
                let event = match agent_field::build_event(&agent_keys, &owner, &body, created_at) {
                    Ok(e) => e,
                    Err(e) => {
                        tracing::warn!(target: "pool::agent_fields", key, "NIP-AF: build failed: {e}");
                        continue;
                    }
                };
                match tokio::time::timeout(PUBLISH_TIMEOUT, rest_client.submit_event(&event)).await
                {
                    Ok(Ok(resp))
                        if resp.get("accepted") == Some(&serde_json::Value::Bool(false)) =>
                    {
                        tracing::warn!(target: "pool::agent_fields", key, "NIP-AF: rejected: {resp}");
                    }
                    Ok(Ok(_)) => this.mark_published(key, value),
                    Ok(Err(RelayError::Http(message))) if is_unknown_kind_rejection(&message) => {
                        tracing::info!(
                            target: "pool::agent_fields",
                            "NIP-AF: relay does not support agent fields; not publishing them"
                        );
                        this.disable();
                        return;
                    }
                    Ok(Err(e)) => {
                        tracing::warn!(target: "pool::agent_fields", key, "NIP-AF: publish failed: {e}");
                    }
                    Err(_) => {
                        tracing::warn!(target: "pool::agent_fields", key, "NIP-AF: publish timed out");
                    }
                }
            }
        });
    }
}

/// The relay rejects kinds it does not know with HTTP 400
/// `{"error":"restricted: unknown event kind"}`.
fn is_unknown_kind_rejection(message: &str) -> bool {
    message.contains("HTTP 400") && message.contains("unknown event kind")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn usage(model: Option<&str>, context: Option<(u64, u64)>, cost: Option<f64>) -> TurnUsage {
        TurnUsage {
            session_id: "s".into(),
            turn_seq: 1,
            delta_reliable: false,
            turn_input_tokens: None,
            turn_output_tokens: None,
            turn_total_tokens: None,
            turn_cost_usd: None,
            turn_cache_read_tokens: None,
            turn_cache_write_tokens: None,
            cumulative_input_tokens: None,
            cumulative_output_tokens: None,
            cumulative_total_tokens: None,
            cumulative_cost_usd: cost,
            cumulative_cache_read_tokens: None,
            cumulative_cache_write_tokens: None,
            model: model.map(str::to_string),
            pricing_identity: None,
            context_tokens: context,
        }
    }

    #[test]
    fn emits_known_values_and_skips_unchanged_ones() {
        let fields = AgentFields::new("goose".into(), Some("configured".into()), None);

        // No usage: configured model, no thinking/context/cost.
        assert_eq!(
            fields.changed(None),
            vec![
                (keys::HARNESS, "goose".into()),
                (keys::MODEL, "configured".into())
            ]
        );

        let turn = usage(Some("live"), Some((41_250, 200_000)), Some(0.41213));
        let first = fields.changed(Some(&turn));
        assert_eq!(
            first,
            vec![
                (keys::HARNESS, "goose".into()),
                (keys::MODEL, "live".into()),
                (keys::CONTEXT, "41250/200000".into()),
                (keys::COST, "0.4121".into()),
            ]
        );
        for (k, v) in first {
            fields.mark_published(k, v);
        }

        let next = usage(Some("live"), Some((50_000, 200_000)), Some(0.41213));
        assert_eq!(
            fields.changed(Some(&next)),
            vec![(keys::CONTEXT, "50000/200000".into())]
        );

        assert_eq!(fields.next_created_at(100), 100);
        assert_eq!(
            fields.next_created_at(100),
            101,
            "same-second turns still replace"
        );

        fields.disable();
        assert!(fields.changed(Some(&next)).is_empty());
    }

    #[tokio::test]
    async fn old_relay_rejection_disables_publishing() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let mut request = vec![0; 16 * 1024];
                let _ = socket.read(&mut request).await;
                let body = r#"{"error":"restricted: unknown event kind"}"#;
                let response = format!(
                    "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
            }
        });
        let agent = nostr::Keys::generate();
        let rest = RestClient {
            http: reqwest::Client::new(),
            base_url,
            keys: agent.clone(),
            auth_tag_json: None,
        };
        let fields = Arc::new(AgentFields::new("goose".into(), None, None));

        fields.publish(&rest, &agent, nostr::Keys::generate().public_key(), None);
        tokio::time::timeout(Duration::from_secs(5), async {
            while !fields.changed(None).is_empty() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("publishing is disabled after the relay rejects the kind");
        server.abort();
    }
}
