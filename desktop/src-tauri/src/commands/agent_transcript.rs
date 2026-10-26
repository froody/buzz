use buzz_core_pkg::agent_transcript::{open, Manifest};
use sha2::{Digest, Sha256};
use tauri::State;

use crate::app_state::AppState;
use crate::commands::media_download::{fetch_blob_bytes_with_cap, validate_download_url};
use crate::relay::relay_api_base_url_with_override;

/// Largest transcript blob (segment or page) the viewer downloads.
const MAX_TRANSCRIPT_BLOB_BYTES: u64 = 16 * 1024 * 1024;

/// Fetch, verify, and decrypt one blob referenced by a transcript manifest.
/// `manifest` is the field value (the root manifest that carries the key).
async fn read_blob(
    manifest: &str,
    sha256: &str,
    state: &State<'_, AppState>,
) -> Result<Vec<u8>, String> {
    let key = Manifest::parse(manifest)
        .and_then(|manifest| manifest.blob_key())
        .map_err(|e| e.to_string())?;
    let sha256 = sha256.to_ascii_lowercase();
    if sha256.len() != 64 || !sha256.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("invalid transcript blob sha256".to_string());
    }
    let relay_base = relay_api_base_url_with_override(state);
    let url = format!("{}/media/{sha256}", relay_base.trim_end_matches('/'));
    validate_download_url(&url, &relay_base)?;
    let blob = fetch_blob_bytes_with_cap(&url, state, MAX_TRANSCRIPT_BLOB_BYTES, None).await?;
    open_verified(key.as_ref(), &sha256, &blob)
}

fn open_verified(key: Option<&[u8; 32]>, sha256: &str, blob: &[u8]) -> Result<Vec<u8>, String> {
    if hex::encode(Sha256::digest(blob)) != sha256 {
        return Err("transcript blob does not match its sha256".to_string());
    }
    open(key, blob).map_err(|e| e.to_string())
}

/// Observer frames from a segment: one JSON object per line; lines that are
/// not JSON objects are skipped.
fn parse_frames(plaintext: &[u8]) -> Vec<serde_json::Value> {
    String::from_utf8_lossy(plaintext)
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(serde_json::Value::is_object)
        .collect()
}

fn parse_page(plaintext: &[u8]) -> Result<Manifest, String> {
    let json = std::str::from_utf8(plaintext).map_err(|e| format!("invalid page: {e}"))?;
    Manifest::parse(json).map_err(|e| e.to_string())
}

/// Download and decode one transcript segment into its NIP-AO observer frames.
#[tauri::command]
pub async fn read_agent_transcript_segment(
    manifest: String,
    sha256: String,
    state: State<'_, AppState>,
) -> Result<Vec<serde_json::Value>, String> {
    let plaintext = read_blob(&manifest, &sha256, &state).await?;
    Ok(parse_frames(&plaintext))
}

/// Download and decode an `earlier` page of a transcript manifest.
#[tauri::command]
pub async fn read_agent_transcript_page(
    manifest: String,
    sha256: String,
    state: State<'_, AppState>,
) -> Result<Manifest, String> {
    let plaintext = read_blob(&manifest, &sha256, &state).await?;
    parse_page(&plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use buzz_core_pkg::agent_transcript::{generate_key, seal, Segment};

    fn sealed(key: &[u8; 32], plaintext: &[u8]) -> (String, Vec<u8>) {
        let blob = seal(Some(key), plaintext);
        (hex::encode(Sha256::digest(&blob)), blob)
    }

    #[test]
    fn transcript_blobs_open_with_the_manifest_key_only() {
        let key = generate_key();
        let (seg_sha, seg_blob) = sealed(
            &key,
            b"{\"seq\":1,\"kind\":\"acp\"}\nnot json\n[1]\n{\"seq\":2,\"kind\":\"acp\"}\n",
        );
        let frames = parse_frames(&open_verified(Some(&key), &seg_sha, &seg_blob).unwrap());
        assert_eq!(
            frames.iter().map(|f| f["seq"].as_u64()).collect::<Vec<_>>(),
            [Some(1), Some(2)]
        );

        let mut page = Manifest::new(None);
        page.segments.push(Segment {
            sha256: seg_sha.clone(),
            size: seg_blob.len() as u64,
            turn_id: None,
            at: 7,
        });
        page.earlier = Some("older".into());
        let (page_sha, page_blob) = sealed(&key, page.to_json().as_bytes());
        let opened = parse_page(&open_verified(Some(&key), &page_sha, &page_blob).unwrap());
        assert_eq!(opened.unwrap(), page);

        let wrong = generate_key();
        assert!(open_verified(Some(&wrong), &seg_sha, &seg_blob).is_err());
        assert!(open_verified(Some(&key), &page_sha, &seg_blob).is_err());
    }
}
