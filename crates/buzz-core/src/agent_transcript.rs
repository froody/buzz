//! NIP-AF transcript manifests and segment encryption (`docs/nips/NIP-AF.md`,
//! *Transcripts*). I/O-free: callers upload and fetch the Blossom blobs.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};

/// Prefix of every encrypted blob. Fixed leading bytes keep Blossom's magic-byte
/// sniffing from classifying random ciphertext as an image or audio file.
pub const BLOB_MAGIC: &[u8; 8] = b"BUZZAF1\n";

const NONCE_LEN: usize = 24;

/// Errors from transcript blob handling.
#[derive(Debug, thiserror::Error)]
pub enum TranscriptError {
    /// The blob is not a well-formed encrypted blob for this key.
    #[error("cannot decrypt transcript blob")]
    Decrypt,
    /// The manifest key is not 32 base64-encoded bytes.
    #[error("invalid transcript key")]
    InvalidKey,
    /// The manifest or page JSON is malformed.
    #[error("invalid manifest: {0}")]
    InvalidManifest(String),
}

/// One uploaded segment: newline-delimited NIP-AO observer frames.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Segment {
    /// Blossom sha256 of the uploaded blob (ciphertext when encrypted).
    pub sha256: String,
    /// Uploaded blob size in bytes.
    pub size: u64,
    /// Turn the segment covers, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub turn_id: Option<String>,
    /// Unix seconds when the segment was written.
    pub at: u64,
}

/// The `transcript` field value, and the shape of every `earlier` page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// Format version; this module writes and reads `1`.
    pub v: u32,
    /// Segments, oldest first.
    pub segments: Vec<Segment>,
    /// sha256 of the blob holding the next-older page, if any.
    #[serde(default)]
    pub earlier: Option<String>,
    /// Base64 blob key; present on owner-only manifests, never on pages.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
}

impl Manifest {
    /// An empty manifest. `key` is `Some` for owner-only transcripts.
    pub fn new(key: Option<&[u8; 32]>) -> Self {
        Self {
            v: 1,
            segments: Vec::new(),
            earlier: None,
            key: key.map(|k| STANDARD.encode(k)),
        }
    }

    /// Parse a field value or a decrypted page.
    pub fn parse(json: &str) -> Result<Self, TranscriptError> {
        let manifest: Self = serde_json::from_str(json)
            .map_err(|e| TranscriptError::InvalidManifest(e.to_string()))?;
        if manifest.v != 1 {
            return Err(TranscriptError::InvalidManifest(format!(
                "unsupported version {}",
                manifest.v
            )));
        }
        Ok(manifest)
    }

    /// Serialize for the field value or a page blob.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    /// The decoded blob key, if this manifest is encrypted.
    pub fn blob_key(&self) -> Result<Option<[u8; 32]>, TranscriptError> {
        self.key
            .as_deref()
            .map(|k| {
                STANDARD
                    .decode(k)
                    .ok()
                    .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
                    .ok_or(TranscriptError::InvalidKey)
            })
            .transpose()
    }

    /// When the serialized manifest exceeds `max_bytes`, move the oldest half
    /// of the segments into a page and return it. The caller uploads the
    /// page (encrypted like segments), then sets `earlier` to its sha256.
    pub fn take_overflow(&mut self, max_bytes: usize) -> Option<Manifest> {
        if self.to_json().len() <= max_bytes || self.segments.len() < 2 {
            return None;
        }
        let newer = self.segments.split_off(self.segments.len() / 2);
        Some(Manifest {
            v: 1,
            segments: std::mem::replace(&mut self.segments, newer),
            earlier: self.earlier.take(),
            key: None,
        })
    }
}

/// A fresh random blob key.
pub fn generate_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    rand::fill(&mut key);
    key
}

/// Encode a blob for upload: `BLOB_MAGIC || nonce || ciphertext` with a key,
/// the plaintext unchanged without one.
pub fn seal(key: Option<&[u8; 32]>, plaintext: &[u8]) -> Vec<u8> {
    let Some(key) = key else {
        return plaintext.to_vec();
    };
    let mut nonce = [0u8; NONCE_LEN];
    rand::fill(&mut nonce);
    let ciphertext = XChaCha20Poly1305::new(key.into())
        .encrypt(XNonce::from_slice(&nonce), plaintext)
        .unwrap_or_default();
    [BLOB_MAGIC.as_slice(), &nonce, &ciphertext].concat()
}

/// Decode a downloaded blob; the inverse of [`seal`].
pub fn open(key: Option<&[u8; 32]>, blob: &[u8]) -> Result<Vec<u8>, TranscriptError> {
    let Some(key) = key else {
        return Ok(blob.to_vec());
    };
    let rest = blob
        .strip_prefix(BLOB_MAGIC.as_slice())
        .filter(|rest| rest.len() >= NONCE_LEN)
        .ok_or(TranscriptError::Decrypt)?;
    let (nonce, ciphertext) = rest.split_at(NONCE_LEN);
    XChaCha20Poly1305::new(key.into())
        .decrypt(XNonce::from_slice(nonce), ciphertext)
        .map_err(|_| TranscriptError::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealed_blobs_open_only_with_their_key_and_never_sniff_as_media() {
        let key = generate_key();
        let blob = seal(Some(&key), b"{\"kind\":\"acp_read\"}\n");
        assert!(blob.starts_with(BLOB_MAGIC));
        assert_eq!(
            open(Some(&key), &blob).unwrap(),
            b"{\"kind\":\"acp_read\"}\n"
        );
        assert!(open(Some(&generate_key()), &blob).is_err());
        let mut tampered = blob.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(open(Some(&key), &tampered).is_err());
        assert_eq!(open(None, b"plain").unwrap(), b"plain");
    }

    #[test]
    fn overflow_pages_keep_order_and_chain() {
        let key = generate_key();
        let mut manifest = Manifest::new(Some(&key));
        manifest.earlier = Some("old".into());
        for i in 0..10 {
            manifest.segments.push(Segment {
                sha256: format!("{i:064}"),
                size: 1,
                turn_id: None,
                at: i,
            });
        }
        assert!(manifest.take_overflow(usize::MAX).is_none());
        let page = manifest.take_overflow(100).unwrap();
        let ats = |m: &Manifest| m.segments.iter().map(|s| s.at).collect::<Vec<_>>();
        assert_eq!(ats(&page), [0, 1, 2, 3, 4]);
        assert_eq!(ats(&manifest), [5, 6, 7, 8, 9]);
        assert_eq!(page.earlier.as_deref(), Some("old"));
        assert_eq!(page.key, None, "pages never carry the key");
        assert_eq!(
            manifest.earlier, None,
            "caller sets it after uploading the page"
        );

        let parsed = Manifest::parse(&manifest.to_json()).unwrap();
        assert_eq!(parsed.blob_key().unwrap(), Some(key));
        assert!(Manifest::parse(r#"{"v":2,"segments":[]}"#).is_err());
    }
}
