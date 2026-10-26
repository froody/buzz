//! Opt-in NIP-AF transcript publishing (`docs/nips/NIP-AF.md`, *Transcripts*).
//!
//! Observer frames are serialized one per line and buffered per turn. A turn's
//! buffer becomes one segment when the turn ends (`turn_completed` or
//! `turn_error`) or the buffer reaches [`SEGMENT_MAX_BYTES`]. A single uploader
//! task uploads segments strictly in order and republishes the `transcript`
//! field after each one, so the manifest has exactly one writer.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use buzz_core::agent_field::{self, keys, FieldBody, FieldType, Visibility};
use buzz_core::agent_transcript::{self, Manifest, Segment};
use buzz_core::engram::monotonic_created_at;
use buzz_core::kind::KIND_AGENT_FIELD;
use nostr::{Event, Filter, Keys, Kind, PublicKey};
use tokio::sync::{broadcast, Notify};

use crate::agent_fields::is_unknown_kind_rejection;
use crate::observer::{ObserverEvent, ObserverHandle};
use crate::relay::{RelayError, RestClient};

/// A turn's buffer is flushed as a segment once it reaches this size.
const SEGMENT_MAX_BYTES: usize = 1024 * 1024;
/// Most unsent segment bytes kept while uploads fail.
const UNSENT_MAX_BYTES: usize = 8 * 1024 * 1024;
/// Manifest bytes kept below the field body limit, leaving room for the body envelope.
const MANIFEST_MAX_BYTES: usize = agent_field::BODY_MAX_BYTES - 1024;
const RETRY_BASE_DELAY: Duration = Duration::from_secs(15);
const RETRY_MAX_DELAY: Duration = Duration::from_secs(600);
const PUBLISH_TIMEOUT: Duration = Duration::from_secs(10);

struct PendingSegment {
    turn_id: Option<String>,
    at: u64,
    jsonl: Vec<u8>,
}

/// Groups observer frames into per-turn segments.
#[derive(Default)]
struct Segmenter {
    /// Frames outside any turn; they lead the next segment.
    untagged: Vec<u8>,
    turns: HashMap<String, Vec<u8>>,
}

impl Segmenter {
    /// Buffer one frame; returns a segment when it ends a turn or fills a buffer.
    fn push(&mut self, event: &ObserverEvent, now: u64) -> Option<PendingSegment> {
        let mut line = match serde_json::to_vec(event) {
            Ok(line) => line,
            Err(e) => {
                tracing::warn!(target: "transcript", "NIP-AF: frame serialize failed: {e}");
                return None;
            }
        };
        line.push(b'\n');
        let turn_ended = matches!(event.kind.as_str(), "turn_completed" | "turn_error");
        // A turn emits both terminal frames (`turn_error` after
        // `turn_completed`); the later one leads the next segment.
        let turn_id = event
            .turn_id
            .clone()
            .filter(|id| !turn_ended || self.turns.contains_key(id));
        let Some(turn_id) = turn_id else {
            self.untagged.extend(line);
            return (self.untagged.len() >= SEGMENT_MAX_BYTES).then(|| PendingSegment {
                turn_id: None,
                at: now,
                jsonl: std::mem::take(&mut self.untagged),
            });
        };
        let buffer = self.turns.entry(turn_id.clone()).or_default();
        buffer.extend(line);
        if !turn_ended && buffer.len() < SEGMENT_MAX_BYTES {
            return None;
        }
        let mut jsonl = std::mem::take(&mut self.untagged);
        jsonl.extend(self.turns.remove(&turn_id).unwrap_or_default());
        Some(PendingSegment {
            turn_id: Some(turn_id),
            at: now,
            jsonl,
        })
    }
}

/// Segments waiting for upload, bounded to [`UNSENT_MAX_BYTES`]: when uploads
/// keep failing, the oldest segments are dropped (with a warning) first.
#[derive(Default)]
struct UnsentQueue {
    segments: VecDeque<PendingSegment>,
    bytes: usize,
}

impl UnsentQueue {
    fn push(&mut self, segment: PendingSegment) {
        self.bytes += segment.jsonl.len();
        self.segments.push_back(segment);
        while self.bytes > UNSENT_MAX_BYTES {
            let Some(dropped) = self.segments.pop_front() else {
                break;
            };
            self.bytes -= dropped.jsonl.len();
            tracing::warn!(
                target: "transcript",
                turn_id = dropped.turn_id.as_deref().unwrap_or("-"),
                bytes = dropped.jsonl.len(),
                "NIP-AF: transcript upload backlog full; dropping oldest segment"
            );
        }
    }

    fn pop(&mut self) -> Option<PendingSegment> {
        let segment = self.segments.pop_front()?;
        self.bytes -= segment.jsonl.len();
        Some(segment)
    }

    /// Return a segment whose upload failed to the front of the queue.
    fn unpop(&mut self, segment: PendingSegment) {
        self.bytes += segment.jsonl.len();
        self.segments.push_front(segment);
    }
}

#[derive(Default)]
struct Shared {
    queue: Mutex<UnsentQueue>,
    wake: Notify,
}

impl Shared {
    fn push(&self, segment: PendingSegment) {
        self.queue
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(segment);
        self.wake.notify_one();
    }

    fn pop(&self) -> Option<PendingSegment> {
        self.queue.lock().unwrap_or_else(|e| e.into_inner()).pop()
    }

    fn unpop(&self, segment: PendingSegment) {
        self.queue
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .unpop(segment);
    }
}

/// Start publishing the observer feed as the agent's `transcript` field.
///
/// Returns the collector task; aborting it also stops the uploader.
pub fn spawn(
    observer: &ObserverHandle,
    rest_client: RestClient,
    agent_keys: Keys,
    owner: PublicKey,
    visibility: Visibility,
) -> tokio::task::JoinHandle<()> {
    // Subscribe before snapshotting; overlap is deduped by `seq`.
    let mut rx = observer.subscribe();
    let snapshot = observer.snapshot();
    let shared = Arc::new(Shared::default());
    let uploader = tokio::spawn(
        Uploader {
            rest_client,
            agent_keys,
            owner,
            visibility,
            manifest: None,
            dirty: false,
            last_created_at: 0,
        }
        .run(Arc::clone(&shared)),
    );
    tokio::spawn(async move {
        let mut segmenter = Segmenter::default();
        let max_snapshot_seq = snapshot.iter().map(|e| e.seq).max().unwrap_or(0);
        let mut ingest = |event: &ObserverEvent| {
            if let Some(segment) = segmenter.push(event, nostr::Timestamp::now().as_secs()) {
                shared.push(segment);
            }
        };
        snapshot.iter().for_each(&mut ingest);
        loop {
            if uploader.is_finished() {
                return;
            }
            match rx.recv().await {
                Ok(event) if event.seq > max_snapshot_seq => ingest(&event),
                Ok(_) => {}
                Err(broadcast::error::RecvError::Lagged(count)) => {
                    tracing::warn!(target: "transcript", dropped = count, "NIP-AF: transcript collector lagged");
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
        uploader.abort();
    })
}

enum StepError {
    /// The relay does not support agent fields.
    Unsupported,
    Retry(String),
}

impl From<RelayError> for StepError {
    fn from(error: RelayError) -> Self {
        match error {
            RelayError::Http(message) if is_unknown_kind_rejection(&message) => Self::Unsupported,
            other => Self::Retry(other.to_string()),
        }
    }
}

struct Uploader {
    rest_client: RestClient,
    agent_keys: Keys,
    owner: PublicKey,
    visibility: Visibility,
    /// Loaded lazily from the relay on the first segment.
    manifest: Option<Manifest>,
    /// The manifest has segments the relay's field does not list yet.
    dirty: bool,
    last_created_at: u64,
}

impl Uploader {
    async fn run(mut self, shared: Arc<Shared>) {
        let mut delay = RETRY_BASE_DELAY;
        loop {
            let result = if self.dirty {
                self.publish().await
            } else if let Some(segment) = shared.pop() {
                let result = self.append(&segment).await;
                if result.is_err() {
                    shared.unpop(segment);
                }
                result
            } else {
                shared.wake.notified().await;
                continue;
            };
            match result {
                Ok(()) => delay = RETRY_BASE_DELAY,
                Err(StepError::Unsupported) => {
                    tracing::info!(target: "transcript", "NIP-AF: relay does not support agent fields; not publishing the transcript");
                    return;
                }
                Err(StepError::Retry(message)) => {
                    tracing::warn!(target: "transcript", "NIP-AF: transcript publish failed, retrying in {}s: {message}", delay.as_secs());
                    tokio::time::sleep(delay).await;
                    delay = (delay * 2).min(RETRY_MAX_DELAY);
                }
            }
        }
    }

    /// Upload a segment (and any overflow page) and add it to the manifest.
    /// The manifest is only replaced once every upload succeeded.
    async fn append(&mut self, segment: &PendingSegment) -> Result<(), StepError> {
        let mut manifest = match self.manifest.take() {
            Some(manifest) => manifest,
            None => self.load().await?,
        };
        let result = self.append_to(&mut manifest, segment).await;
        self.manifest = Some(manifest);
        result
    }

    async fn append_to(
        &mut self,
        manifest: &mut Manifest,
        segment: &PendingSegment,
    ) -> Result<(), StepError> {
        let key = manifest
            .blob_key()
            .map_err(|e| StepError::Retry(format!("manifest key: {e}")))?;
        let mut next = manifest.clone();
        let blob = agent_transcript::seal(key.as_ref(), &segment.jsonl);
        let size = blob.len() as u64;
        next.segments.push(Segment {
            sha256: self.rest_client.upload_blob(blob).await?,
            size,
            turn_id: segment.turn_id.clone(),
            at: segment.at,
        });
        while let Some(page) = next.take_overflow(MANIFEST_MAX_BYTES) {
            let blob = agent_transcript::seal(key.as_ref(), page.to_json().as_bytes());
            next.earlier = Some(self.rest_client.upload_blob(blob).await?);
        }
        *manifest = next;
        self.dirty = true;
        Ok(())
    }

    /// Continue the published manifest when its visibility matches; else start a new one.
    async fn load(&mut self) -> Result<Manifest, StepError> {
        let k_c = agent_field::conversation_key(self.agent_keys.secret_key(), &self.owner);
        let filter = Filter::new()
            .kind(Kind::Custom(KIND_AGENT_FIELD as u16))
            .author(self.agent_keys.public_key())
            .identifier(agent_field::d_tag(&k_c, keys::TRANSCRIPT));
        let events = self.rest_client.query(&[filter]).await?;
        let newest = events
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|v| serde_json::from_value::<Event>(v.clone()).ok())
            .filter(|e| e.verify().is_ok())
            .max_by_key(|e| e.created_at);
        if let Some(event) = &newest {
            self.last_created_at = self.last_created_at.max(event.created_at.as_secs());
        }
        let existing = newest
            .and_then(|event| {
                agent_field::read_event(&event, Some((self.agent_keys.secret_key(), &self.owner)))
                    .ok()
            })
            .filter(|body| {
                body.visibility == self.visibility && body.field_type == FieldType::Transcript
            })
            .and_then(|body| Manifest::parse(body.value.as_deref()?).ok())
            .filter(|manifest| {
                matches!(
                    (self.visibility, manifest.blob_key()),
                    (Visibility::Owner, Ok(Some(_))) | (Visibility::Community, Ok(None))
                )
            });
        Ok(existing.unwrap_or_else(|| match self.visibility {
            Visibility::Owner => Manifest::new(Some(&agent_transcript::generate_key())),
            Visibility::Community => Manifest::new(None),
        }))
    }

    async fn publish(&mut self) -> Result<(), StepError> {
        let Some(manifest) = &self.manifest else {
            self.dirty = false;
            return Ok(());
        };
        let body = FieldBody {
            key: keys::TRANSCRIPT.to_string(),
            value: Some(manifest.to_json()),
            field_type: FieldType::Transcript,
            visibility: self.visibility,
        };
        self.last_created_at = monotonic_created_at(
            nostr::Timestamp::now().as_secs(),
            Some(self.last_created_at),
        );
        let event =
            agent_field::build_event(&self.agent_keys, &self.owner, &body, self.last_created_at)
                .map_err(|e| StepError::Retry(format!("build: {e}")))?;
        let response = tokio::time::timeout(PUBLISH_TIMEOUT, self.rest_client.submit_event(&event))
            .await
            .map_err(|_| StepError::Retry("publish timed out".into()))??;
        if response.get("accepted") == Some(&serde_json::Value::Bool(false)) {
            return Err(StepError::Retry(format!("rejected: {response}")));
        }
        self.dirty = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observer::{context_for, ObserverContext};

    fn frame(
        seq: u64,
        kind: &str,
        turn_id: Option<&str>,
        payload: serde_json::Value,
    ) -> ObserverEvent {
        ObserverEvent {
            seq,
            timestamp: "2026-10-26T00:00:00Z".into(),
            kind: kind.into(),
            agent_index: Some(0),
            channel_id: None,
            session_id: None,
            turn_id: turn_id.map(str::to_string),
            started_at: None,
            payload,
        }
    }

    fn kinds(jsonl: &[u8]) -> Vec<String> {
        jsonl
            .split(|b| *b == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| {
                let value: serde_json::Value = serde_json::from_slice(line).unwrap();
                value["kind"].as_str().unwrap().to_string()
            })
            .collect()
    }

    #[test]
    fn segments_per_turn_and_bounds_the_backlog() {
        let mut segmenter = Segmenter::default();
        let null = serde_json::Value::Null;
        assert!(segmenter
            .push(&frame(1, "harness_started", None, null.clone()), 7)
            .is_none());
        assert!(segmenter
            .push(&frame(2, "turn_started", Some("a"), null.clone()), 7)
            .is_none());
        assert!(segmenter
            .push(&frame(3, "turn_started", Some("b"), null.clone()), 7)
            .is_none());
        let a = segmenter
            .push(&frame(4, "turn_completed", Some("a"), null.clone()), 8)
            .expect("turn end flushes the turn");
        assert_eq!(a.turn_id.as_deref(), Some("a"));
        assert_eq!(a.at, 8);
        assert_eq!(
            kinds(&a.jsonl),
            ["harness_started", "turn_started", "turn_completed"]
        );
        assert!(
            segmenter
                .push(&frame(6, "turn_error", Some("a"), null.clone()), 8)
                .is_none(),
            "the second terminal frame of a finished turn does not make its own segment"
        );

        let big = serde_json::json!("x".repeat(SEGMENT_MAX_BYTES));
        let b = segmenter
            .push(&frame(5, "acp_read", Some("b"), big), 9)
            .expect("a full buffer flushes mid-turn");
        assert_eq!(kinds(&b.jsonl), ["turn_error", "turn_started", "acp_read"]);
        assert!(segmenter.turns.is_empty());

        let mut queue = UnsentQueue::default();
        for turn in 0..10 {
            queue.push(PendingSegment {
                turn_id: Some(turn.to_string()),
                at: 0,
                jsonl: vec![0; SEGMENT_MAX_BYTES],
            });
        }
        assert_eq!(queue.bytes, UNSENT_MAX_BYTES);
        let oldest = queue.pop().expect("queue keeps the newest segments");
        assert_eq!(oldest.turn_id.as_deref(), Some("2"));
        queue.unpop(oldest);
        assert_eq!(queue.segments.len(), 8);
        assert_eq!(queue.bytes, UNSENT_MAX_BYTES);
    }

    /// Minimal HTTP/1.1 relay: stores `PUT /upload` blobs, answers `/query`
    /// with no events, and forwards each `POST /events` body.
    async fn serve(
        listener: tokio::net::TcpListener,
        blobs: Arc<Mutex<HashMap<String, Vec<u8>>>>,
        events: tokio::sync::mpsc::UnboundedSender<Event>,
    ) {
        use sha2::Digest;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        while let Ok((mut socket, _)) = listener.accept().await {
            let mut request = Vec::new();
            let mut chunk = vec![0; 64 * 1024];
            let (head_len, method, path, body_len) = loop {
                let n = socket.read(&mut chunk).await.unwrap();
                request.extend_from_slice(&chunk[..n]);
                let mut headers = [httparse::EMPTY_HEADER; 32];
                let mut parsed = httparse::Request::new(&mut headers);
                if let httparse::Status::Complete(len) = parsed.parse(&request).unwrap() {
                    let body_len = parsed
                        .headers
                        .iter()
                        .find(|h| h.name.eq_ignore_ascii_case("content-length"))
                        .map(|h| {
                            std::str::from_utf8(h.value)
                                .unwrap()
                                .parse::<usize>()
                                .unwrap()
                        })
                        .unwrap_or(0);
                    break (
                        len,
                        parsed.method.unwrap().to_string(),
                        parsed.path.unwrap().to_string(),
                        body_len,
                    );
                }
            };
            while request.len() < head_len + body_len {
                let n = socket.read(&mut chunk).await.unwrap();
                request.extend_from_slice(&chunk[..n]);
            }
            let body = request[head_len..head_len + body_len].to_vec();
            let response = match (method.as_str(), path.as_str()) {
                ("PUT", "/upload") => {
                    let sha256 = hex::encode(sha2::Sha256::digest(&body));
                    let descriptor = serde_json::json!({"sha256": sha256, "size": body.len()});
                    blobs.lock().unwrap().insert(sha256, body);
                    descriptor.to_string()
                }
                ("POST", "/query") => "[]".to_string(),
                ("POST", "/events") => {
                    let _ = events.send(serde_json::from_slice(&body).unwrap());
                    r#"{"accepted":true}"#.to_string()
                }
                _ => panic!("unexpected {method} {path}"),
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",
                response.len()
            );
            let _ = socket.write_all(response.as_bytes()).await;
        }
    }

    #[tokio::test]
    async fn publishes_an_encrypted_segment_listed_by_the_manifest() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let blobs = Arc::new(Mutex::new(HashMap::new()));
        let (events_tx, mut events_rx) = tokio::sync::mpsc::unbounded_channel();
        let server = tokio::spawn(serve(listener, Arc::clone(&blobs), events_tx));

        let agent = Keys::generate();
        let owner = Keys::generate();
        let rest = RestClient {
            http: reqwest::Client::new(),
            base_url,
            keys: agent.clone(),
            auth_tag_json: None,
        };
        let observer = ObserverHandle::in_process();
        observer.emit(
            "harness_started",
            None,
            &ObserverContext::default(),
            serde_json::json!({}),
        );
        let task = spawn(
            &observer,
            rest,
            agent.clone(),
            owner.public_key(),
            Visibility::Owner,
        );
        let turn = context_for(None, Some("s".into()), Some("t1".into()));
        observer.emit("turn_started", Some(0), &turn, serde_json::json!({}));
        observer.emit(
            "acp_read",
            Some(0),
            &turn,
            serde_json::json!({"secret": "hello"}),
        );
        observer.emit("turn_completed", Some(0), &turn, serde_json::json!({}));

        let event = tokio::time::timeout(Duration::from_secs(10), events_rx.recv())
            .await
            .expect("transcript field published")
            .unwrap();
        let body = agent_field::read_event(&event, Some((owner.secret_key(), &agent.public_key())))
            .unwrap();
        assert_eq!(body.key, keys::TRANSCRIPT);
        assert_eq!(body.field_type, FieldType::Transcript);
        let manifest = Manifest::parse(body.value.as_deref().unwrap()).unwrap();
        let [segment] = manifest.segments.as_slice() else {
            panic!("one segment: {manifest:?}");
        };
        assert_eq!(segment.turn_id.as_deref(), Some("t1"));
        let blob = blobs.lock().unwrap()[&segment.sha256].clone();
        assert_eq!(segment.size, blob.len() as u64);
        assert!(
            !blob.windows(5).any(|w| w == b"hello"),
            "segment is encrypted"
        );
        let jsonl = agent_transcript::open(manifest.blob_key().unwrap().as_ref(), &blob).unwrap();
        assert_eq!(
            kinds(&jsonl),
            [
                "harness_started",
                "turn_started",
                "acp_read",
                "turn_completed"
            ]
        );
        task.abort();
        server.abort();
    }
}
