//! Email verification page for the profile gate.
//!
//! A gated member signs in with their Workspace Google account, gives their
//! Buzz public key, and proves they hold it by putting a one-time code in
//! their profile description (the one signed write a gated member can still
//! make). The relay then appends `<pubkey> <email>` to the verified file the
//! gate reads.
//!
//! The ID token comes straight from Google's token endpoint over TLS, so,
//! per OpenID Connect Core §3.1.3.7, TLS stands in for checking its signature.

use std::sync::{Arc, OnceLock};

use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{AppendHeaders, Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Form, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, KeyInit, Mac};
use serde::Deserialize;
use sha2::Sha256;
use tracing::{info, warn};

use crate::config::ProfileVerifyConfig;
use crate::state::AppState;
use buzz_core::tenant::TenantContext;

const PAGE: &str = "/verify";
const CALLBACK: &str = "/verify/callback";
const SESSION_COOKIE: &str = "buzz_verify_session";
const STATE_COOKIE: &str = "buzz_verify_state";
const SESSION_SECS: i64 = 30 * 60;

/// Routes for the verify page, mounted when email verification is configured.
pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route(PAGE, get(page))
        .route("/verify/login", get(login))
        .route(CALLBACK, get(callback))
        .route("/verify/key", post(key))
        .route("/verify/check", post(check))
        .with_state(state)
}

/// The verify page URL for a community host.
pub(crate) fn page_url(host: &str) -> String {
    format!("https://{host}{PAGE}")
}

/// Per-process key for session cookies and profile codes. A restart signs
/// everyone out of the verify page; verified emails are already on disk.
fn secret() -> &'static [u8; 32] {
    static SECRET: OnceLock<[u8; 32]> = OnceLock::new();
    SECRET.get_or_init(rand::random)
}

fn mac(parts: &[&str]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret()).expect("HMAC accepts any key size");
    for part in parts {
        mac.update(part.as_bytes());
        mac.update(&[0]);
    }
    mac.finalize().into_bytes().to_vec()
}

fn verify_config(state: &AppState) -> &ProfileVerifyConfig {
    state
        .config
        .profile_verify
        .as_ref()
        .expect("verify routes are mounted only when configured")
}

async fn tenant(state: &AppState, headers: &HeaderMap) -> Result<TenantContext, Response> {
    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    crate::tenant::bind_community(&state.db, host)
        .await
        .map_err(|_| {
            (
                StatusCode::NOT_FOUND,
                "no community is configured for this host",
            )
                .into_response()
        })
}

fn cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find_map(|(k, v)| (k == name).then_some(v))
}

fn set_cookie(name: &str, value: &str, max_age: i64) -> (header::HeaderName, String) {
    (
        header::SET_COOKIE,
        format!("{name}={value}; Path={PAGE}; Max-Age={max_age}; HttpOnly; Secure; SameSite=Lax"),
    )
}

/// The signed-in email, from a session cookie `email.expiry.mac`.
fn session_email(headers: &HeaderMap) -> Option<String> {
    let (email_b64, rest) = cookie(headers, SESSION_COOKIE)?.split_once('.')?;
    let (expiry, tag) = rest.split_once('.')?;
    let email = String::from_utf8(URL_SAFE_NO_PAD.decode(email_b64).ok()?).ok()?;
    let fresh = expiry.parse::<i64>().ok()? > chrono::Utc::now().timestamp();
    let expected = URL_SAFE_NO_PAD.encode(mac(&["session", &email, expiry]));
    (fresh && subtle::ConstantTimeEq::ct_eq(expected.as_bytes(), tag.as_bytes()).into())
        .then_some(email)
}

fn session_cookie(email: &str) -> (header::HeaderName, String) {
    let expiry = (chrono::Utc::now().timestamp() + SESSION_SECS).to_string();
    let tag = URL_SAFE_NO_PAD.encode(mac(&["session", email, &expiry]));
    let value = format!("{}.{expiry}.{tag}", URL_SAFE_NO_PAD.encode(email));
    set_cookie(SESSION_COOKIE, &value, SESSION_SECS)
}

/// The code a key must put in its profile to prove it belongs to `email`.
fn profile_code(pubkey: &nostr::PublicKey, email: &str) -> String {
    format!(
        "buzz-verify-{}",
        &hex::encode(mac(&["code", &pubkey.to_hex(), email]))[..10]
    )
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn render(community: &str, body: &str) -> Response {
    Html(format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Verify your email · {community}</title>
<style>
body{{font:16px/1.5 system-ui,sans-serif;max-width:34rem;margin:3rem auto;padding:0 1rem;color:#4c4f69}}
h1{{font-size:1.4rem}} code{{background:#eff1f5;padding:.1rem .3rem;border-radius:4px;user-select:all}}
input{{font:inherit;width:100%;padding:.5rem;box-sizing:border-box;margin:.25rem 0 1rem}}
button,.button{{font:inherit;padding:.5rem 1rem;border-radius:6px;border:0;background:#1e66f5;color:#fff;text-decoration:none;cursor:pointer}}
.error{{color:#d20f39}} .ok{{color:#40a02b}}
</style></head><body><h1>Verify your email for {community}</h1>{body}</body></html>"#,
        community = escape(community),
    ))
    .into_response()
}

fn key_form(error: &str, npub: &str) -> String {
    let error = if error.is_empty() {
        String::new()
    } else {
        format!(r#"<p class="error">{}</p>"#, escape(error))
    };
    format!(
        r#"{error}<form method="post" action="/verify/key">
<label for="npub">Your Buzz public key. In Buzz, open Settings → Profile → Identity → Public key and copy it.</label>
<input id="npub" name="npub" required placeholder="npub1…" value="{}" autocomplete="off" spellcheck="false">
<button>Continue</button></form>"#,
        escape(npub)
    )
}

async fn page(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let tenant = match tenant(&state, &headers).await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let domain = &verify_config(&state).domain;
    let body = match session_email(&headers) {
        None => format!(
            r#"<p>Before you can post, link your Buzz key to your @{domain} account.</p>
<p><a class="button" href="/verify/login">Sign in with Google</a></p>"#
        ),
        Some(email) => format!(
            r#"<p>Signed in as <b>{}</b>.</p>{}"#,
            escape(&email),
            key_form("", "")
        ),
    };
    render(tenant.host(), &body)
}

fn google_base(config: &ProfileVerifyConfig) -> (String, String) {
    match &config.google_url {
        Some(base) => (format!("{base}/o/oauth2/v2/auth"), format!("{base}/token")),
        None => (
            "https://accounts.google.com/o/oauth2/v2/auth".into(),
            "https://oauth2.googleapis.com/token".into(),
        ),
    }
}

fn redirect_uri(tenant: &TenantContext) -> String {
    format!("https://{}{CALLBACK}", tenant.host())
}

async fn login(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let tenant = match tenant(&state, &headers).await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let config = verify_config(&state);
    let nonce = hex::encode(rand::random::<[u8; 16]>());
    let mut url = url::Url::parse(&google_base(config).0).expect("static Google URL");
    url.query_pairs_mut()
        .append_pair("client_id", &config.client_id)
        .append_pair("redirect_uri", &redirect_uri(&tenant))
        .append_pair("response_type", "code")
        .append_pair("scope", "openid email")
        .append_pair("hd", &config.domain)
        .append_pair("prompt", "select_account")
        .append_pair("state", &nonce);
    (
        [set_cookie(STATE_COOKIE, &nonce, 600)],
        Redirect::to(url.as_str()),
    )
        .into_response()
}

#[derive(Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct IdClaims {
    iss: String,
    aud: String,
    exp: i64,
    email: String,
    #[serde(default)]
    email_verified: bool,
    hd: Option<String>,
}

/// Exchange an authorization code for the signed-in Workspace email.
async fn exchange(
    config: &ProfileVerifyConfig,
    tenant: &TenantContext,
    code: &str,
) -> Result<String, String> {
    let body = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "authorization_code")
        .append_pair("code", code)
        .append_pair("client_id", &config.client_id)
        .append_pair("client_secret", config.client_secret())
        .append_pair("redirect_uri", &redirect_uri(tenant))
        .finish();
    let response: serde_json::Value = reqwest::Client::new()
        .post(google_base(config).1)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(|e| format!("token request: {e}"))?
        .json()
        .await
        .map_err(|e| format!("token response: {e}"))?;
    let id_token = response["id_token"].as_str().ok_or("no id_token")?;
    let payload = id_token.split('.').nth(1).ok_or("malformed id_token")?;
    let claims: IdClaims = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| "malformed id_token")?,
    )
    .map_err(|e| format!("id_token claims: {e}"))?;
    let issuers = match &config.google_url {
        Some(base) => vec![base.as_str()],
        None => vec!["https://accounts.google.com", "accounts.google.com"],
    };
    let email = claims.email.to_ascii_lowercase();
    let valid = issuers.contains(&claims.iss.as_str())
        && claims.aud == config.client_id
        && claims.exp > chrono::Utc::now().timestamp()
        && claims.email_verified
        && claims.hd.as_deref() == Some(config.domain.as_str())
        && email.ends_with(&format!("@{}", config.domain));
    valid
        .then_some(email)
        .ok_or_else(|| "account is not a verified Workspace account".into())
}

async fn callback(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<CallbackQuery>,
) -> Response {
    let tenant = match tenant(&state, &headers).await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let config = verify_config(&state);
    let retry = r#"<p><a class="button" href="/verify/login">Try again</a></p>"#;
    let state_matches =
        query.state.is_some() && query.state.as_deref() == cookie(&headers, STATE_COOKIE);
    let (Some(code), true, None) = (&query.code, state_matches, &query.error) else {
        return render(
            tenant.host(),
            &format!(r#"<p class="error">Google sign-in didn't complete.</p>{retry}"#),
        );
    };
    match exchange(config, &tenant, code).await {
        Ok(email) => (
            AppendHeaders([session_cookie(&email), set_cookie(STATE_COOKIE, "", 0)]),
            Redirect::to(PAGE),
        )
            .into_response(),
        Err(e) => {
            warn!(error = %e, "profile verify: Google sign-in rejected");
            render(
                tenant.host(),
                &format!(
                    r#"<p class="error">Sign in with your @{} Google account.</p>{retry}"#,
                    config.domain
                ),
            )
        }
    }
}

#[derive(Deserialize)]
struct KeyForm {
    npub: String,
}

/// Show the profile code for the submitted key, or the check result.
async fn key_or_check(
    state: Arc<AppState>,
    headers: HeaderMap,
    form: KeyForm,
    checking: bool,
) -> Response {
    let tenant = match tenant(&state, &headers).await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let Some(email) = session_email(&headers) else {
        return Redirect::to(PAGE).into_response();
    };
    let signed_in = format!("<p>Signed in as <b>{}</b>.</p>", escape(&email));
    let Ok(pubkey) = nostr::PublicKey::parse(form.npub.trim()) else {
        return render(
            tenant.host(),
            &(signed_in + &key_form("That isn't a Buzz public key.", &form.npub)),
        );
    };
    let npub = nostr::ToBech32::to_bech32(&pubkey).unwrap_or_else(|_| pubkey.to_hex());
    let code = profile_code(&pubkey, &email);
    let mut notice = String::new();
    if checking {
        let about = match state
            .db
            .get_user(tenant.community(), &pubkey.to_bytes())
            .await
        {
            Ok(user) => user.and_then(|u| u.about).unwrap_or_default(),
            Err(e) => {
                warn!(error = %e, "profile verify: reading profile failed");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "could not read your profile; try again",
                )
                    .into_response();
            }
        };
        if about.contains(&code) {
            return match record(verify_config(&state), &pubkey, &email) {
                Ok(()) => render(
                    tenant.host(),
                    &format!(
                        r#"{signed_in}<p class="ok"><b>Verified.</b> Your Buzz key is linked to {email}.</p>
<p>Last step: in Buzz, open Settings → Profile and replace <code>{code}</code> in your
profile description with <code>{email}</code>. You can post once you save.</p>"#,
                        email = escape(&email)
                    ),
                ),
                Err(e) => {
                    warn!(error = %e, "profile verify: writing verified file failed");
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "could not save your verification; try again",
                    )
                        .into_response()
                }
            };
        }
        notice = r#"<p class="error">The code isn't in your profile description yet. Save your profile in Buzz, then check again.</p>"#.into();
    }
    render(
        tenant.host(),
        &format!(
            r#"{signed_in}<p>Key: <code>{npub}</code></p>{notice}
<ol><li>In Buzz, open Settings → Profile.</li>
<li>Add this code to your <b>Profile description</b> and save: <code>{code}</code></li>
<li>Come back and press Check.</li></ol>
<form method="post" action="/verify/check"><input type="hidden" name="npub" value="{npub}">
<button>Check</button></form>
<p><small>The code proves you hold this key: only your Buzz app can change your profile.</small></p>"#
        ),
    )
}

async fn key(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<KeyForm>,
) -> Response {
    key_or_check(state, headers, form, false).await
}

async fn check(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<KeyForm>,
) -> Response {
    key_or_check(state, headers, form, true).await
}

/// Append `<pubkey> <email>` to the verified file.
fn record(
    config: &ProfileVerifyConfig,
    pubkey: &nostr::PublicKey,
    email: &str,
) -> std::io::Result<()> {
    use std::io::Write;
    let line = format!(
        "{} {email}  # verified {}\n",
        pubkey.to_hex(),
        chrono::Utc::now().format("%Y-%m-%d")
    );
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&config.verified_file)?
        .write_all(line.as_bytes())?;
    info!(pubkey = %pubkey.to_hex(), email, "profile verify: email verified");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_cookie_round_trips_and_rejects_tampering() {
        let (_, set) = session_cookie("jon@neara.com");
        let value = set
            .split(';')
            .next()
            .unwrap()
            .split_once('=')
            .unwrap()
            .1
            .to_string();
        let headers = |value: &str| {
            let mut h = HeaderMap::new();
            h.insert(
                header::COOKIE,
                format!("other=1; {SESSION_COOKIE}={value}")
                    .parse()
                    .unwrap(),
            );
            h
        };
        assert_eq!(
            session_email(&headers(&value)).as_deref(),
            Some("jon@neara.com")
        );
        let forged = value.replacen(
            &URL_SAFE_NO_PAD.encode("jon@neara.com"),
            &URL_SAFE_NO_PAD.encode("tom@neara.com"),
            1,
        );
        assert_eq!(session_email(&headers(&forged)), None);
    }

    #[test]
    fn profile_code_binds_key_and_email() {
        let (a, b) = (
            nostr::Keys::generate().public_key(),
            nostr::Keys::generate().public_key(),
        );
        assert_eq!(
            profile_code(&a, "jon@neara.com"),
            profile_code(&a, "jon@neara.com")
        );
        assert_ne!(
            profile_code(&a, "jon@neara.com"),
            profile_code(&b, "jon@neara.com")
        );
        assert_ne!(
            profile_code(&a, "jon@neara.com"),
            profile_code(&a, "tom@neara.com")
        );
    }
}
