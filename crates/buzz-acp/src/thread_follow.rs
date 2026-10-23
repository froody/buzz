//! Opt-in thread following for mentions mode (`--follow-threads`).
//!
//! Without it, a mentions-mode agent only hears events that `p`-tag it, so a
//! human's plain reply in a thread the agent is already part of never reaches
//! it. With it, the relay subscription drops its `#p` filter and this module
//! admits the subset of untagged traffic that continues the agent's own
//! conversation:
//!
//! - a kind:9 / kind:40002 thread reply (it has a NIP-10 root);
//! - that `p`-tags nobody — a reply that addresses someone else stays theirs
//!   (a reply that tags this agent already matched the mention rule);
//! - in a thread whose root or replies this agent wrote or was mentioned in;
//! - whose author is not provably an agent (NIP-OA `auth` tag on the event or
//!   on the author's kind:0), so two following agents cannot wake each other
//!   in a loop.
//!
//! Every lookup failure rejects: an unverifiable reply is dropped, never
//! admitted.

use std::time::Duration;

use nostr::{Alphabet, Event, EventId, Filter, Kind, PublicKey, SingleLetterTag};
use uuid::Uuid;

use crate::relay::{RelayError, RestClient};

/// Prompt tag for an admitted reply, rendered as `<buzz-event type="…">`.
pub(crate) const THREAD_REPLY_PROMPT_TAG: &str = "thread-reply";

/// Bound for the single admission lookup. Matches the other bounded
/// admission lookups on the listener loop (see `check_sibling_via_profile`).
const THREAD_FOLLOW_FETCH_TIMEOUT: Duration = Duration::from_millis(2_000);

const MESSAGE_KINDS: [u32; 2] = [
    buzz_core::kind::KIND_STREAM_MESSAGE,
    buzz_core::kind::KIND_STREAM_MESSAGE_V2,
];

/// Whether `event` is an untagged human reply in a thread this agent takes
/// part in. See the module docs for the rules.
pub(crate) async fn admits_thread_reply(
    event: &Event,
    channel_id: Uuid,
    agent: &PublicKey,
    rest: &RestClient,
) -> bool {
    admits_thread_reply_with(event, channel_id, agent, |filters| async move {
        rest.query(&filters).await
    })
    .await
}

pub(crate) async fn admits_thread_reply_with<Query, QueryFut>(
    event: &Event,
    channel_id: Uuid,
    agent: &PublicKey,
    query: Query,
) -> bool
where
    Query: FnOnce(Vec<Filter>) -> QueryFut,
    QueryFut: std::future::Future<Output = Result<serde_json::Value, RelayError>>,
{
    if !MESSAGE_KINDS.contains(&u32::from(event.kind.as_u16())) {
        return false;
    }
    let Some((root, _parent)) = buzz_core::nip10::parse_thread_markers(&event.tags).resolve()
    else {
        return false;
    };
    if p_tags(event).next().is_some() || carries_auth_tag(event) {
        return false;
    }
    let Ok(root_id) = EventId::from_hex(&root) else {
        return false;
    };

    let channel = channel_id.to_string();
    let kinds = MESSAGE_KINDS.map(|kind| Kind::Custom(kind as u16));
    let in_channel = || {
        Filter::new()
            .kinds(kinds)
            .custom_tags(SingleLetterTag::lowercase(Alphabet::H), [channel.as_str()])
    };
    let in_thread =
        || in_channel().custom_tags(SingleLetterTag::lowercase(Alphabet::E), [root.as_str()]);
    let filters = vec![
        // The root itself: the agent may have started or been tagged in it.
        in_channel().id(root_id).limit(1),
        // A reply the agent posted in the thread.
        in_thread().author(*agent).limit(1),
        // A reply that mentioned the agent.
        in_thread()
            .custom_tags(SingleLetterTag::lowercase(Alphabet::P), [agent.to_hex()])
            .limit(1),
        // The author's profile, to tell agents from humans.
        Filter::new()
            .kind(Kind::Metadata)
            .author(event.pubkey)
            .limit(1),
    ];

    let events = match tokio::time::timeout(THREAD_FOLLOW_FETCH_TIMEOUT, query(filters)).await {
        Ok(Ok(serde_json::Value::Array(events))) => events,
        Ok(Ok(_)) => {
            tracing::warn!(event_id = %event.id, "thread follow: non-array lookup response");
            return false;
        }
        Ok(Err(error)) => {
            tracing::warn!(event_id = %event.id, "thread follow: lookup failed: {error}");
            return false;
        }
        Err(_) => {
            tracing::warn!(event_id = %event.id, "thread follow: lookup timed out");
            return false;
        }
    };

    let mut participates = false;
    for raw in events {
        let Ok(found) = serde_json::from_value::<Event>(raw) else {
            continue;
        };
        if found.kind == Kind::Metadata {
            if found.pubkey == event.pubkey && carries_auth_tag(&found) {
                tracing::debug!(event_id = %event.id, author = %event.pubkey, "thread follow: author is an agent");
                return false;
            }
            continue;
        }
        // Every message filter is scoped to this thread; the root filter alone
        // does not constrain author or mentions, so check both here.
        let agent_hex = agent.to_hex();
        if found.pubkey == *agent || p_tags(&found).any(|p| p == agent_hex) {
            participates = true;
        }
    }
    participates
}

fn p_tags(event: &Event) -> impl Iterator<Item = &str> {
    event.tags.iter().filter_map(|tag| match tag.as_slice() {
        [kind, value, ..] if kind == "p" => Some(value.as_str()),
        _ => None,
    })
}

/// A NIP-OA `auth` tag whose attestation verifies for the event's author.
fn carries_auth_tag(event: &Event) -> bool {
    event.tags.iter().any(|tag| {
        tag.as_slice().first().map(String::as_str) == Some("auth")
            && serde_json::to_string(tag.as_slice())
                .is_ok_and(|json| buzz_sdk::nip_oa::verify_auth_tag(&json, &event.pubkey).is_ok())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::filter::MatchEventOptions;
    use nostr::{EventBuilder, Keys, Tag};

    struct Fixture {
        channel: Uuid,
        agent: Keys,
        owner: Keys,
        human: Keys,
        store: Vec<Event>,
    }

    impl Fixture {
        fn new() -> Self {
            Self {
                channel: Uuid::new_v4(),
                agent: Keys::generate(),
                owner: Keys::generate(),
                human: Keys::generate(),
                store: Vec::new(),
            }
        }

        /// Store a channel message by `author`; `reply_to` makes it a direct
        /// reply to that root. `extra` adds raw tags.
        fn post(&mut self, author: &Keys, reply_to: Option<EventId>, extra: Vec<Tag>) -> Event {
            let mut tags = vec![Tag::parse(["h", &self.channel.to_string()]).unwrap()];
            if let Some(root) = reply_to {
                tags.push(Tag::parse(["e", &root.to_hex(), "", "reply"]).unwrap());
            }
            tags.extend(extra);
            let event = EventBuilder::new(
                Kind::Custom(buzz_core::kind::KIND_STREAM_MESSAGE as u16),
                "hi",
            )
            .tags(tags)
            .sign_with_keys(author)
            .unwrap();
            self.store.push(event.clone());
            event
        }

        fn mention(keys: &Keys) -> Tag {
            Tag::parse(["p", &keys.public_key().to_hex()]).unwrap()
        }

        /// A tag the owner signs to attest `agent` as theirs.
        fn auth_tag(owner: &Keys, agent: &Keys) -> Tag {
            let json = buzz_sdk::nip_oa::compute_auth_tag(owner, &agent.public_key(), "").unwrap();
            let parts: Vec<String> = serde_json::from_str(&json).unwrap();
            Tag::parse(parts).unwrap()
        }

        /// Run the gate against a fake relay that applies the real filters
        /// to the stored events, as `/query` does.
        async fn admits(&self, event: &Event) -> bool {
            let store = self.store.clone();
            admits_thread_reply_with(
                event,
                self.channel,
                &self.agent.public_key(),
                |filters| async move {
                    let hits: Vec<_> = store
                        .iter()
                        .filter(|e| {
                            filters
                                .iter()
                                .any(|f| f.match_event(e, MatchEventOptions::new()))
                        })
                        .collect();
                    Ok(serde_json::to_value(hits).unwrap())
                },
            )
            .await
        }
    }

    #[tokio::test]
    async fn admits_only_untagged_human_replies_in_threads_the_agent_is_in() {
        let mut fx = Fixture::new();
        let human = fx.human.clone();
        let agent = fx.agent.clone();

        // Agent was mentioned in a root, then a human replies without a tag.
        let mentioned_root = fx.post(&human, None, vec![Fixture::mention(&agent)]);
        let reply = fx.post(&human, Some(mentioned_root.id), vec![]);
        assert!(
            fx.admits(&reply).await,
            "reply in a thread that mentioned the agent"
        );

        // Agent posted in a thread whose root never mentioned it.
        let plain_root = fx.post(&human, None, vec![]);
        let before = fx.post(&human, Some(plain_root.id), vec![]);
        assert!(
            !fx.admits(&before).await,
            "agent has not joined this thread yet"
        );
        fx.post(&agent, Some(plain_root.id), vec![]);
        let after = fx.post(&human, Some(plain_root.id), vec![]);
        assert!(
            fx.admits(&after).await,
            "reply in a thread the agent posted in"
        );

        // Agent started the thread.
        let agent_root = fx.post(&agent, None, vec![]);
        let to_agent = fx.post(&human, Some(agent_root.id), vec![]);
        assert!(
            fx.admits(&to_agent).await,
            "reply in a thread the agent started"
        );

        // Unrelated channel chatter: top-level, or in someone else's thread.
        let top_level = fx.post(&human, None, vec![]);
        assert!(!fx.admits(&top_level).await, "top-level chatter");
        let other_root = fx.post(&human, None, vec![Fixture::mention(&fx.owner.clone())]);
        let other_reply = fx.post(&human, Some(other_root.id), vec![]);
        assert!(
            !fx.admits(&other_reply).await,
            "thread the agent is not part of"
        );

        // A reply that addresses someone else stays theirs.
        let owner = fx.owner.clone();
        let redirected = fx.post(
            &human,
            Some(mentioned_root.id),
            vec![Fixture::mention(&owner)],
        );
        assert!(
            !fx.admits(&redirected).await,
            "reply that @mentions someone else"
        );

        // Another agent's untagged reply must not wake us (loop guard): an
        // auth tag on the event, or on the author's kind:0 profile.
        let bot = Keys::generate();
        let tagged_bot = fx.post(
            &bot,
            Some(mentioned_root.id),
            vec![Fixture::auth_tag(&owner, &bot)],
        );
        assert!(
            !fx.admits(&tagged_bot).await,
            "agent reply carrying an auth tag"
        );
        let quiet_bot = Keys::generate();
        let profile = EventBuilder::new(Kind::Metadata, "{}")
            .tags([Fixture::auth_tag(&owner, &quiet_bot)])
            .sign_with_keys(&quiet_bot)
            .unwrap();
        fx.store.push(profile);
        let untagged_bot = fx.post(&quiet_bot, Some(mentioned_root.id), vec![]);
        assert!(
            !fx.admits(&untagged_bot).await,
            "agent whose profile is attested"
        );
    }

    #[tokio::test]
    async fn lookup_failure_rejects() {
        let mut fx = Fixture::new();
        let human = fx.human.clone();
        let root = fx.post(&human, None, vec![Fixture::mention(&fx.agent.clone())]);
        let reply = fx.post(&human, Some(root.id), vec![]);
        let admitted =
            admits_thread_reply_with(&reply, fx.channel, &fx.agent.public_key(), |_| async {
                Err(RelayError::Http("down".into()))
            })
            .await;
        assert!(!admitted);
    }
}
