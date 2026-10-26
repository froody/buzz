//! NIP-AF Agent Fields — pure crypto + parsing primitives.
//!
//! See `docs/nips/NIP-AF.md`. I/O-free, shared by `buzz-acp` (harness-written
//! fields), `buzz-cli` (`buzz agent fields …`) and the desktop.

use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use nostr::nips::nip44::{self, v2::ConversationKey, Version};
use nostr::{Event, EventBuilder, Keys, Kind, PublicKey, SecretKey, Tag};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::kind::KIND_AGENT_FIELD;

/// Domain prefix for the `d`-tag HMAC, followed by `0x00` and the key.
pub const D_TAG_DOMAIN: &[u8] = b"agent-field/v1/d-tag";

/// Maximum serialized body size in bytes.
pub const BODY_MAX_BYTES: usize = 16_384;

/// Maximum event `content` size the relay accepts (covers NIP-44 expansion).
pub const CONTENT_MAX_BYTES: usize = 32 * 1024;

/// Reserved keys (spec: *Keys*).
pub mod keys {
    /// Harness identifier.
    pub const HARNESS: &str = "harness";
    /// Current model identifier.
    pub const MODEL: &str = "model";
    /// Thinking / effort level.
    pub const THINKING: &str = "thinking";
    /// `"<used>/<limit>"` tokens.
    pub const CONTEXT: &str = "context";
    /// Session-cumulative estimated USD cost.
    pub const COST: &str = "cost";
    /// Transcript manifest.
    pub const TRANSCRIPT: &str = "transcript";
}

/// Errors from agent field operations.
#[derive(Debug, thiserror::Error)]
pub enum AgentFieldError {
    /// Key failed the *Keys* grammar.
    #[error("invalid key: {0}")]
    InvalidKey(String),
    /// Envelope (kind, tags) is not a valid agent field.
    #[error("invalid envelope: {0}")]
    InvalidEnvelope(String),
    /// Body failed to parse or disagrees with its envelope.
    #[error("invalid body: {0}")]
    InvalidBody(String),
    /// Body uses a visibility or type this reader does not know; skip it.
    #[error("unsupported field: {0}")]
    Unsupported(String),
    /// The reader cannot decrypt this owner-only field.
    #[error("not readable by this reader")]
    NotReadable,
    /// Body is over [`BODY_MAX_BYTES`].
    #[error("body exceeds {BODY_MAX_BYTES} bytes ({0})")]
    BodyTooLarge(usize),
    /// Encryption or signing failed.
    #[error("build failed: {0}")]
    Build(String),
}

/// Who can read a field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Visibility {
    /// Only the agent and its owner (NIP-44 under `K_c`).
    Owner,
    /// Every community member (plaintext).
    Community,
}

/// How a field's value is interpreted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FieldType {
    /// Free text.
    Text,
    /// A transcript manifest (spec: *Transcripts*).
    Transcript,
}

/// A decoded field body. `value == None` is a tombstone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldBody {
    /// The field's key.
    pub key: String,
    /// The value, or `None` once removed.
    pub value: Option<String>,
    /// How to interpret `value`.
    #[serde(rename = "type")]
    pub field_type: FieldType,
    /// Who can read this field.
    pub visibility: Visibility,
}

/// Validate a key against `^[a-z0-9][a-z0-9_.-]{0,63}$`.
pub fn validate_key(key: &str) -> Result<(), AgentFieldError> {
    let bytes = key.as_bytes();
    let valid = !bytes.is_empty()
        && bytes.len() <= 64
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_.-".contains(b));
    if valid {
        Ok(())
    } else {
        Err(AgentFieldError::InvalidKey(key.to_string()))
    }
}

/// `K_c` for the agent ↔ owner pair; symmetric between the two.
pub fn conversation_key(my_seckey: &SecretKey, their_pubkey: &PublicKey) -> ConversationKey {
    ConversationKey::derive(my_seckey, their_pubkey).expect("valid keys produce conversation key")
}

/// `d = lower_hex(HMAC-SHA256(K_c, "agent-field/v1/d-tag" || 0x00 || key))`.
pub fn d_tag(k_c: &ConversationKey, key: &str) -> String {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(k_c.as_bytes())
        .expect("HMAC-SHA256 accepts keys of any length");
    mac.update(D_TAG_DOMAIN);
    mac.update(&[0u8]);
    mac.update(key.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Build and sign a field event. Tombstones are always owner-only so that a
/// removed key's name is not left in plaintext.
pub fn build_event(
    agent_keys: &Keys,
    owner_pubkey: &PublicKey,
    body: &FieldBody,
    created_at: u64,
) -> Result<Event, AgentFieldError> {
    validate_key(&body.key)?;
    let mut body = body.clone();
    if body.value.is_none() {
        body.visibility = Visibility::Owner;
    }
    let json = serde_json::to_string(&body).map_err(|e| AgentFieldError::Build(e.to_string()))?;
    if json.len() > BODY_MAX_BYTES {
        return Err(AgentFieldError::BodyTooLarge(json.len()));
    }
    let k_c = conversation_key(agent_keys.secret_key(), owner_pubkey);
    let d = Tag::parse(["d", &d_tag(&k_c, &body.key)])
        .map_err(|e| AgentFieldError::Build(e.to_string()))?;
    let (content, tags) = match body.visibility {
        Visibility::Owner => {
            let ciphertext =
                nip44::encrypt(agent_keys.secret_key(), owner_pubkey, &json, Version::V2)
                    .map_err(|e| AgentFieldError::Build(e.to_string()))?;
            let p = Tag::parse(["p", &owner_pubkey.to_hex()])
                .map_err(|e| AgentFieldError::Build(e.to_string()))?;
            (ciphertext, vec![d, p])
        }
        Visibility::Community => (json, vec![d]),
    };
    EventBuilder::new(Kind::Custom(KIND_AGENT_FIELD as u16), content)
        .tags(tags)
        .custom_created_at(nostr::Timestamp::from(created_at))
        .sign_with_keys(agent_keys)
        .map_err(|e| AgentFieldError::Build(e.to_string()))
}

/// The tag shape every valid field event has (spec: *Event*). Shared by
/// relay ingest and readers.
pub struct Envelope<'a> {
    /// The `d` tag value (64 lowercase hex).
    pub d: &'a str,
    /// The owner, when the content is encrypted.
    pub owner: Option<&'a str>,
}

/// Validate the envelope of a field event without decrypting it.
pub fn validate_envelope(event: &Event) -> Result<Envelope<'_>, AgentFieldError> {
    if event.kind.as_u16() as u32 != KIND_AGENT_FIELD {
        return Err(AgentFieldError::InvalidEnvelope("wrong kind".into()));
    }
    if event.content.len() > CONTENT_MAX_BYTES {
        return Err(AgentFieldError::InvalidEnvelope(format!(
            "content exceeds {CONTENT_MAX_BYTES} bytes"
        )));
    }
    let mut d = None;
    let mut owner = None;
    for tag in event.tags.iter() {
        let parts = tag.as_slice();
        let (Some(name), value) = (parts.first(), parts.get(1)) else {
            continue;
        };
        let slot = match name.as_str() {
            "d" => &mut d,
            "p" => &mut owner,
            "h" => {
                return Err(AgentFieldError::InvalidEnvelope(
                    "must not have an h tag".into(),
                ))
            }
            _ => continue,
        };
        let value = value.filter(|v| is_lower_hex_64(v)).ok_or_else(|| {
            AgentFieldError::InvalidEnvelope(format!("{name} tag must be 64 lowercase hex"))
        })?;
        if slot.replace(value.as_str()).is_some() {
            return Err(AgentFieldError::InvalidEnvelope(format!(
                "more than one {name} tag"
            )));
        }
    }
    let d = d.ok_or_else(|| AgentFieldError::InvalidEnvelope("missing d tag".into()))?;
    Ok(Envelope { d, owner })
}

fn is_lower_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Decode a field event for a reader. The caller verifies the signature first.
///
/// `owner_keys` is `Some((my_seckey, their_pubkey))` when the reader is the
/// agent or its owner; it enables decryption and the `d`-tag check. Other
/// readers pass `None` and can read only community fields.
pub fn read_event(
    event: &Event,
    owner_keys: Option<(&SecretKey, &PublicKey)>,
) -> Result<FieldBody, AgentFieldError> {
    let envelope = validate_envelope(event)?;
    let json = match (envelope.owner, owner_keys) {
        (None, _) => event.content.clone(),
        (Some(_), Some((my_seckey, their_pubkey))) => {
            nip44::decrypt(my_seckey, their_pubkey, &event.content)
                .map_err(|_| AgentFieldError::NotReadable)?
        }
        (Some(_), None) => return Err(AgentFieldError::NotReadable),
    };
    let raw: serde_json::Value =
        serde_json::from_str(&json).map_err(|e| AgentFieldError::InvalidBody(e.to_string()))?;
    for (field, known) in [
        ("visibility", &["owner", "community"][..]),
        ("type", &["text", "transcript"][..]),
    ] {
        if let Some(value) = raw.get(field).and_then(|v| v.as_str()) {
            if !known.contains(&value) {
                return Err(AgentFieldError::Unsupported(format!("{field} {value}")));
            }
        }
    }
    let body: FieldBody =
        serde_json::from_value(raw).map_err(|e| AgentFieldError::InvalidBody(e.to_string()))?;
    validate_key(&body.key)?;
    if (body.visibility == Visibility::Owner) != envelope.owner.is_some() {
        return Err(AgentFieldError::InvalidBody(
            "visibility disagrees with envelope".into(),
        ));
    }
    if let Some((my_seckey, their_pubkey)) = owner_keys {
        let k_c = conversation_key(my_seckey, their_pubkey);
        if d_tag(&k_c, &body.key) != envelope.d {
            return Err(AgentFieldError::InvalidBody(
                "key does not re-derive to d tag".into(),
            ));
        }
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(key: &str, value: Option<&str>, visibility: Visibility) -> FieldBody {
        FieldBody {
            key: key.into(),
            value: value.map(Into::into),
            field_type: FieldType::Text,
            visibility,
        }
    }

    #[test]
    fn owner_and_community_fields_round_trip_for_each_reader() {
        let agent = Keys::generate();
        let owner = Keys::generate();
        let stranger = Keys::generate();
        let as_agent = Some((agent.secret_key(), &owner.public_key()));
        let as_owner = Some((owner.secret_key(), &agent.public_key()));
        let as_stranger = Some((stranger.secret_key(), &agent.public_key()));

        let secret = body("cost", Some("0.42"), Visibility::Owner);
        let event = build_event(&agent, &owner.public_key(), &secret, 1).unwrap();
        assert!(!event.content.contains("cost"), "owner field is encrypted");
        assert_eq!(read_event(&event, as_owner).unwrap(), secret);
        assert_eq!(read_event(&event, as_agent).unwrap(), secret);
        assert!(matches!(
            read_event(&event, None),
            Err(AgentFieldError::NotReadable)
        ));
        assert!(matches!(
            read_event(&event, as_stranger),
            Err(AgentFieldError::NotReadable)
        ));

        let public = body("model", Some("opus"), Visibility::Community);
        let event = build_event(&agent, &owner.public_key(), &public, 1).unwrap();
        assert_eq!(read_event(&event, None).unwrap(), public);
        assert_eq!(read_event(&event, as_owner).unwrap(), public);
    }

    #[test]
    fn visibility_change_replaces_the_same_address_and_tombstones_are_private() {
        let agent = Keys::generate();
        let owner = Keys::generate();
        let owner_pk = owner.public_key();
        let private = build_event(
            &agent,
            &owner_pk,
            &body("model", Some("x"), Visibility::Owner),
            1,
        )
        .unwrap();
        let public = build_event(
            &agent,
            &owner_pk,
            &body("model", Some("x"), Visibility::Community),
            2,
        )
        .unwrap();
        assert_eq!(
            validate_envelope(&private).unwrap().d,
            validate_envelope(&public).unwrap().d
        );

        let removed = build_event(
            &agent,
            &owner_pk,
            &body("model", None, Visibility::Community),
            3,
        )
        .unwrap();
        assert!(validate_envelope(&removed).unwrap().owner.is_some());
        let read = read_event(&removed, Some((owner.secret_key(), &agent.public_key()))).unwrap();
        assert_eq!(read.value, None);
    }

    #[test]
    fn readers_skip_unknown_and_inconsistent_bodies() {
        let agent = Keys::generate();
        let owner = Keys::generate();
        let d = d_tag(
            &conversation_key(agent.secret_key(), &owner.public_key()),
            "k",
        );
        let community = |content: &str| {
            EventBuilder::new(Kind::Custom(KIND_AGENT_FIELD as u16), content)
                .tags([Tag::parse(["d", &d]).unwrap()])
                .sign_with_keys(&agent)
                .unwrap()
        };
        let future = community(r#"{"key":"k","value":"v","type":"text","visibility":"channel"}"#);
        assert!(matches!(
            read_event(&future, None),
            Err(AgentFieldError::Unsupported(_))
        ));
        let future =
            community(r#"{"key":"k","value":"v","type":"chart","visibility":"community"}"#);
        assert!(matches!(
            read_event(&future, None),
            Err(AgentFieldError::Unsupported(_))
        ));
        let lying = community(r#"{"key":"k","value":"v","type":"text","visibility":"owner"}"#);
        assert!(matches!(
            read_event(&lying, None),
            Err(AgentFieldError::InvalidBody(_))
        ));
        let wrong_key =
            community(r#"{"key":"other","value":"v","type":"text","visibility":"community"}"#);
        assert!(
            read_event(&wrong_key, None).is_ok(),
            "strangers cannot check d"
        );
        assert!(matches!(
            read_event(&wrong_key, Some((owner.secret_key(), &agent.public_key()))),
            Err(AgentFieldError::InvalidBody(_))
        ));
    }

    #[test]
    fn envelope_rules() {
        let agent = Keys::generate();
        let hex = "a".repeat(64);
        let event = |tags: Vec<Vec<&str>>| {
            EventBuilder::new(Kind::Custom(KIND_AGENT_FIELD as u16), "{}")
                .tags(tags.into_iter().map(|t| Tag::parse(t).unwrap()))
                .sign_with_keys(&agent)
                .unwrap()
        };
        assert!(validate_envelope(&event(vec![vec!["d", &hex]])).is_ok());
        assert!(validate_envelope(&event(vec![vec!["d", &hex], vec!["p", &hex]])).is_ok());
        for bad in [
            vec![],
            vec![vec!["d", "short"]],
            vec![vec!["d", &hex], vec!["d", &hex]],
            vec![vec!["d", &hex], vec!["p", &hex], vec!["p", &hex]],
            vec![vec!["d", &hex], vec!["h", "chan"]],
        ] {
            assert!(validate_envelope(&event(bad.clone())).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn keys_grammar() {
        for ok in ["cost", "a", "x.y-z_1", &"a".repeat(64)] {
            assert!(validate_key(ok).is_ok(), "{ok}");
        }
        for bad in ["", "Cost", "-a", "a b", "a/b", &"a".repeat(65)] {
            assert!(validate_key(bad).is_err(), "{bad}");
        }
    }
}
