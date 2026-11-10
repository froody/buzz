//! Opt-in profile gate: pubkeys listed in `BUZZ_PROFILE_GATE_FILE` cannot
//! post messages until their profile description (`about`) qualifies.
//!
//! Without email verification, the description needs an email address and a
//! Slack profile link. With it (`BUZZ_PROFILE_VERIFY_FILE`), the description
//! needs an email address the author has linked to their key on the verify
//! page (see [`crate::api::profile_verify`]).
//!
//! Both files are re-read when their mtime changes, so they can be edited
//! without a relay restart. The gate file holds one pubkey per line (hex or
//! npub); the verified file holds `<pubkey> <email>` lines. `#` starts a
//! comment in either.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use buzz_core::kind::{
    KIND_FORUM_COMMENT, KIND_FORUM_POST, KIND_STREAM_MESSAGE, KIND_STREAM_MESSAGE_DIFF,
    KIND_STREAM_MESSAGE_V2, KIND_TEXT_NOTE,
};
use buzz_core::tenant::TenantContext;
use buzz_core::CommunityId;
use tracing::warn;

use super::ingest::IngestError;
use super::moderation_notices::{send_moderation_notice, ModerationNotice};
use crate::state::AppState;

/// Rejection returned to a gated author whose profile is incomplete.
const PROFILE_INCOMPLETE: &str = "restricted: add your email address and Slack profile link \
     to your profile description (Settings → Profile) before posting";

/// How often a gated author is sent the explanatory DM.
const NOTICE_INTERVAL: Duration = Duration::from_secs(60 * 60);

type Pubkey = [u8; 32];

/// Pubkey → emails it has verified.
type Verified = HashMap<Pubkey, HashSet<String>>;

/// A parsed file, re-parsed when its mtime changes.
struct WatchedFile<T> {
    path: PathBuf,
    parse: fn(&str) -> T,
    cached: Mutex<Option<(SystemTime, Arc<T>)>>,
}

impl<T> WatchedFile<T> {
    fn new(path: PathBuf, parse: fn(&str) -> T) -> Self {
        Self {
            path,
            parse,
            cached: Mutex::new(None),
        }
    }

    /// The parsed contents, or `None` when the file can't be read.
    fn get(&self) -> Option<Arc<T>> {
        let read = std::fs::metadata(&self.path)
            .and_then(|m| m.modified())
            .and_then(|modified| {
                let mut cached = self.cached.lock().unwrap_or_else(PoisonError::into_inner);
                match cached.as_ref() {
                    Some((at, value)) if *at == modified => Ok(Arc::clone(value)),
                    _ => {
                        let value = Arc::new((self.parse)(&std::fs::read_to_string(&self.path)?));
                        *cached = Some((modified, Arc::clone(&value)));
                        Ok(value)
                    }
                }
            });
        read.map_err(
            |e| warn!(path = %self.path.display(), error = %e, "profile gate file unreadable"),
        )
        .ok()
    }
}

/// Email verification settings the gate checks profiles against.
struct EmailVerification {
    verified: WatchedFile<Verified>,
    domain: String,
}

/// The gate: who is gated, and what their profile needs.
pub struct ProfileGate {
    gated: WatchedFile<HashSet<Pubkey>>,
    verification: Option<EmailVerification>,
    notified: moka::sync::Cache<(CommunityId, Pubkey), ()>,
}

impl ProfileGate {
    /// Build the gate described by `config`, or `None` when it is off.
    pub fn from_config(config: &crate::config::Config) -> Option<Self> {
        let path = config.profile_gate_file.clone()?;
        let verification = config
            .profile_verify
            .as_ref()
            .map(|verify| EmailVerification {
                verified: WatchedFile::new(verify.verified_file.clone(), parse_verified),
                domain: verify.domain.clone(),
            });
        Some(Self::new(path, verification))
    }

    fn new(path: PathBuf, verification: Option<EmailVerification>) -> Self {
        Self {
            gated: WatchedFile::new(path, parse_gated),
            verification,
            notified: moka::sync::Cache::builder()
                .max_capacity(10_000)
                .time_to_live(NOTICE_INTERVAL)
                .build(),
        }
    }

    /// Whether `pubkey` is listed. An unreadable file gates nobody.
    fn is_gated(&self, pubkey: &Pubkey) -> bool {
        self.gated.get().is_some_and(|set| set.contains(pubkey))
    }
}

impl EmailVerification {
    /// Whether `about` names an email `pubkey` has verified.
    fn verifies(&self, pubkey: &Pubkey, about: &str) -> bool {
        let Some(verified) = self.verified.get() else {
            return false;
        };
        let Some(emails_for_key) = verified.get(pubkey) else {
            return false;
        };
        emails(about).any(|email| emails_for_key.contains(&email))
    }
}

/// Non-comment entries of a gate or verified file.
fn entries(text: &str) -> impl Iterator<Item = &str> {
    text.lines()
        .map(|line| line.split('#').next().unwrap_or_default().trim())
        .filter(|entry| !entry.is_empty())
}

fn parse_pubkey(entry: &str) -> Option<Pubkey> {
    nostr::PublicKey::parse(entry)
        .map(|key| key.to_bytes())
        .map_err(|e| warn!(entry, error = %e, "profile gate: skipping invalid pubkey"))
        .ok()
}

fn parse_gated(text: &str) -> HashSet<Pubkey> {
    entries(text).filter_map(parse_pubkey).collect()
}

fn parse_verified(text: &str) -> Verified {
    let mut verified = Verified::new();
    for entry in entries(text) {
        let mut fields = entry.split_whitespace();
        if let (Some(key), Some(email)) = (fields.next().and_then(parse_pubkey), fields.next()) {
            verified
                .entry(key)
                .or_default()
                .insert(email.to_ascii_lowercase());
        }
    }
    verified
}

/// Kinds that post a message somewhere other members read it.
fn is_gated_kind(kind: u32) -> bool {
    matches!(
        kind,
        KIND_TEXT_NOTE
            | KIND_STREAM_MESSAGE
            | KIND_STREAM_MESSAGE_V2
            | KIND_STREAM_MESSAGE_DIFF
            | KIND_FORUM_POST
            | KIND_FORUM_COMMENT
    )
}

/// Words with surrounding punctuation (`<…>`, `(…)`, trailing `.`) removed.
fn words(text: &str) -> impl Iterator<Item = &str> {
    text.split_whitespace().map(|w| {
        w.trim_matches(|c: char| {
            matches!(
                c,
                '<' | '>' | '(' | ')' | '[' | ']' | ',' | ';' | '.' | '"' | '\''
            )
        })
    })
}

/// Email addresses in `about`, lowercased.
fn emails(about: &str) -> impl Iterator<Item = String> + '_ {
    words(about).filter_map(|w| {
        let w = w.strip_prefix("mailto:").unwrap_or(w);
        let (local, domain) = w.split_once('@')?;
        let valid = !local.is_empty()
            && !w.contains('/')
            && domain.split('.').count() >= 2
            && domain.split('.').all(|label| !label.is_empty());
        valid.then(|| w.to_ascii_lowercase())
    })
}

fn has_slack_profile_link(about: &str) -> bool {
    words(about).any(|w| {
        url::Url::parse(w).is_ok_and(|url| {
            url.scheme() == "https"
                && url.host_str().is_some_and(|h| h.ends_with(".slack.com"))
                && url
                    .path()
                    .strip_prefix("/team/")
                    .is_some_and(|id| !id.trim_matches('/').is_empty())
        })
    })
}

/// Whether a profile description satisfies the gate without email verification.
fn profile_complete(about: &str) -> bool {
    emails(about).next().is_some() && has_slack_profile_link(about)
}

/// Reject a gated message from a listed author whose profile doesn't
/// qualify, and DM them (at most once per [`NOTICE_INTERVAL`]) explaining
/// how to fix it.
pub(crate) async fn enforce_profile_gate(
    state: &Arc<AppState>,
    tenant: &TenantContext,
    kind: u32,
    pubkey: &nostr::PublicKey,
) -> Result<(), IngestError> {
    let Some(gate) = state.profile_gate.as_deref() else {
        return Ok(());
    };
    let key = pubkey.to_bytes();
    if !is_gated_kind(kind) || !gate.is_gated(&key) {
        return Ok(());
    }
    let about = state
        .db
        .get_user(tenant.community(), &key)
        .await
        .map_err(|e| IngestError::Internal(format!("error: internal error reading profile: {e}")))?
        .and_then(|user| user.about)
        .unwrap_or_default();
    let (notice, message) = match &gate.verification {
        None if profile_complete(&about) => return Ok(()),
        None => (
            ModerationNotice::ProfileIncomplete {
                notice_id: uuid::Uuid::new_v4(),
            },
            PROFILE_INCOMPLETE.to_string(),
        ),
        Some(verification) if verification.verifies(&key, &about) => return Ok(()),
        Some(verification) => {
            let verify_url = crate::api::profile_verify::page_url(tenant.host());
            let message = format!(
                "restricted: verify your @{} email before posting: open {verify_url}, then add \
                 the email to your profile description (Settings → Profile)",
                verification.domain
            );
            (
                ModerationNotice::EmailUnverified {
                    notice_id: uuid::Uuid::new_v4(),
                    domain: verification.domain.clone(),
                    verify_url,
                },
                message,
            )
        }
    };
    let notice_key = (tenant.community(), key);
    if !gate.notified.contains_key(&notice_key) {
        gate.notified.insert(notice_key, ());
        let (state, tenant) = (Arc::clone(state), tenant.clone());
        tokio::spawn(async move {
            if let Err(e) =
                send_moderation_notice(&tenant, &state, &key, notice, chrono::Utc::now()).await
            {
                warn!(error = %e, "profile gate notice failed");
                if let Some(gate) = state.profile_gate.as_deref() {
                    gate.notified.invalidate(&(tenant.community(), key));
                }
            }
        });
    }
    Err(IngestError::AuthFailed(message))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_needs_both_email_and_slack_link() {
        let slack = "https://linesoft-plp.slack.com/team/U01CX2R3FQV";
        for (about, complete) in [
            ("", false),
            ("tom@neara.com", false),
            (slack, false),
            (&*format!("Tom. tom@neara.com {slack}"), true),
            (&*format!("Email: <tom@neara.com>, Slack: ({slack})."), true),
            (&*format!("mailto:tom@neara.com\n{slack}/"), true),
            (&*format!("tom@localhost {slack}"), false),
            (&*format!("@tom {slack}"), false),
            ("tom@neara.com https://slack.com/team/U01", false),
            ("tom@neara.com http://x.slack.com/team/U01", false),
            ("tom@neara.com https://x.slack.com/team/", false),
            ("tom@neara.com https://x.slack.com.evil.io/team/U01", false),
        ] {
            assert_eq!(profile_complete(about), complete, "{about:?}");
        }
    }

    #[test]
    fn gate_file_accepts_hex_and_npub_and_skips_comments() {
        let hex = "8ba06048ba9f02efaddeddf16ad89c0e9f3c2003970df687e2b0c7724d71ef14";
        let npub = "npub19pnyjespnkzpgm9gw384qajn275cv5w2zjw7nd65s8z56d3xr24qtc2u5v";
        let set = parse_gated(&format!("# gated\n{hex}  # rod\n\n{npub}\nnot-a-key\n"));
        assert_eq!(set.len(), 2);
        assert!(set.contains(&nostr::PublicKey::parse(npub).unwrap().to_bytes()));
    }

    #[test]
    fn verified_email_must_belong_to_the_key_and_be_in_the_profile() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("verified");
        let (jon, tom) = (
            nostr::Keys::generate().public_key(),
            nostr::Keys::generate().public_key(),
        );
        let verification = EmailVerification {
            verified: WatchedFile::new(path.clone(), parse_verified),
            domain: "neara.com".into(),
        };
        let jon_key = jon.to_bytes();
        assert!(
            !verification.verifies(&jon_key, "jon@neara.com"),
            "missing file verifies nobody"
        );
        std::fs::write(
            &path,
            format!(
                "{} Jon@Neara.com  # 2026-11-10\n{} tom@neara.com\n",
                jon.to_hex(),
                tom.to_hex()
            ),
        )
        .unwrap();
        assert!(verification.verifies(&jon_key, "Hi, I'm Jon (jon@neara.com)."));
        assert!(
            !verification.verifies(&jon_key, "tom@neara.com"),
            "another key's email"
        );
        assert!(!verification.verifies(&jon_key, "no email here"));
        std::thread::sleep(Duration::from_millis(20));
        std::fs::write(&path, format!("{} tom@neara.com\n", tom.to_hex())).unwrap();
        assert!(
            !verification.verifies(&jon_key, "jon@neara.com"),
            "edits apply without restart"
        );
    }
}
