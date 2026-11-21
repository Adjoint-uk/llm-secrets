//! `llms proxy`: a local credential proxy (route mode). See docs/request-scoped-caveats.md.
//!
//! The agent calls `http://127.0.0.1:PORT/<service>/<upstream path>` carrying only a macaroon
//! (`Authorization: Bearer <macaroon>` or `X-Llms-Token`). For every request the proxy:
//!
//! 1. resolves `<service>` in the services file (the upstream host is fixed there, never taken
//!    from the request),
//! 2. builds a `RequestCtx` and verifies the macaroon against it with the existing
//!    `Macaroon::verify` (so `revoke-all` and root-key rotation kill tokens the proxy accepts),
//! 3. strips the agent's credentials, injects the real secret from the store, forwards over
//!    HTTPS without following redirects, and returns the upstream response,
//! 4. audits the decision (never secrets, tokens, query strings or bodies).
//!
//! The agent is treated as hostile: every request field is untrusted and any parse error
//! fails closed.

use std::collections::{BTreeMap, HashSet};
use std::io::{Cursor, Read};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use serde::Deserialize;

use crate::error::{Error, Result};
use crate::macaroon::{Caveat, Context, Macaroon, RequestCtx};

const SERVICES_FILENAME: &str = "services.toml";
const DEFAULT_MAX_BODY: usize = 1024 * 1024;
const MAX_RESPONSE_BODY: u64 = 32 * 1024 * 1024;
const MAX_IN_FLIGHT: usize = 64;
const DEFAULT_BIND: &str = "127.0.0.1:8787";

// ---- config ---------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Inject {
    /// `Authorization: Bearer <secret>`
    Bearer,
    /// `Authorization: Basic base64(<secret>)`; the secret is stored as `user:password`.
    Basic,
    /// `<name>: <secret>`
    Header(String),
}

#[derive(Debug, Clone)]
pub struct Service {
    pub name: String,
    pub host: String,
    pub port: Option<u16>,
    /// Fixed prefix from the configured upstream URL (no trailing slash, may be empty).
    pub base_path: String,
    pub secret: String,
    pub inject: Inject,
    https: bool,
}

#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub max_body: usize,
    pub connect_timeout: Duration,
    pub timeout: Duration,
    pub services: BTreeMap<String, Service>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFile {
    max_body_bytes: Option<usize>,
    connect_timeout_secs: Option<u64>,
    timeout_secs: Option<u64>,
    #[serde(default)]
    services: BTreeMap<String, RawService>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawService {
    upstream: String,
    secret: String,
    inject: String,
    header: Option<String>,
}

pub fn services_path() -> Result<PathBuf> {
    Ok(crate::profile::config_dir()?.join(SERVICES_FILENAME))
}

impl ProxyConfig {
    pub fn load(path: Option<PathBuf>, allow_insecure_upstream: bool) -> Result<Self> {
        let path = match path {
            Some(p) => p,
            None => services_path()?,
        };
        let text = std::fs::read_to_string(&path)
            .map_err(|e| Error::Other(format!("cannot read {}: {e}", path.display())))?;
        Self::parse(&text, allow_insecure_upstream)
            .map_err(|e| Error::Other(format!("{}: {e}", path.display())))
    }

    pub fn parse(text: &str, allow_insecure_upstream: bool) -> std::result::Result<Self, String> {
        let raw: RawFile = toml::from_str(text).map_err(|e| e.to_string())?;
        let mut services = BTreeMap::new();
        for (name, s) in raw.services {
            let valid_name = !name.is_empty()
                && name
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_');
            if !valid_name {
                return Err(format!(
                    "service name '{name}' must be lowercase letters, digits, '-' or '_'"
                ));
            }
            let (https, host, port, base_path) =
                parse_upstream(&s.upstream, allow_insecure_upstream)
                    .map_err(|e| format!("service '{name}': {e}"))?;
            if s.secret.is_empty() {
                return Err(format!("service '{name}': secret name is empty"));
            }
            let inject = match (s.inject.as_str(), s.header) {
                ("bearer", None) => Inject::Bearer,
                ("basic", None) => Inject::Basic,
                ("header", Some(h)) => {
                    let lower = h.to_ascii_lowercase();
                    let token =
                        !h.is_empty() && h.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
                    let reserved = ["host", "content-length", "transfer-encoding", "connection"];
                    if !token || reserved.contains(&lower.as_str()) {
                        return Err(format!("service '{name}': invalid inject header '{h}'"));
                    }
                    Inject::Header(h)
                }
                (other, h) => {
                    return Err(format!(
                        "service '{name}': inject must be \"bearer\", \"basic\" or \"header\" (with `header = ...`); got inject={other:?}, header={h:?}"
                    ));
                }
            };
            services.insert(
                name.clone(),
                Service {
                    name,
                    host,
                    port,
                    base_path,
                    secret: s.secret,
                    inject,
                    https,
                },
            );
        }
        Ok(Self {
            max_body: raw.max_body_bytes.unwrap_or(DEFAULT_MAX_BODY),
            connect_timeout: Duration::from_secs(raw.connect_timeout_secs.unwrap_or(5)),
            timeout: Duration::from_secs(raw.timeout_secs.unwrap_or(30)),
            services,
        })
    }
}

/// Returns `(https, host, port, base_path)`. https only unless `allow_insecure`.
fn parse_upstream(
    s: &str,
    allow_insecure: bool,
) -> std::result::Result<(bool, String, Option<u16>, String), String> {
    let (https, rest) = if let Some(r) = s.strip_prefix("https://") {
        (true, r)
    } else if allow_insecure && let Some(r) = s.strip_prefix("http://") {
        (false, r)
    } else {
        return Err("upstream must be an https:// URL".into());
    };
    if !rest.bytes().all(|b| (0x21..=0x7e).contains(&b))
        || rest.contains(['@', '?', '#', '\\', '[', '%'])
    {
        return Err(
            "upstream has userinfo, query, fragment, IPv6 literal or odd characters".into(),
        );
    }
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => {
            let port: u16 = p.parse().map_err(|_| "invalid upstream port".to_string())?;
            if port == 0 {
                return Err("invalid upstream port".into());
            }
            (h, Some(port))
        }
        None => (authority, None),
    };
    // Reuse the request-side host/path validation so config and requests agree.
    let probe = RequestCtx::new(host, "GET", if path.is_empty() { "/" } else { path }, None)?;
    let base = path.trim_end_matches('/').to_string();
    Ok((https, probe.host, port, base))
}

// ---- strict JSON ----------------------------------------------------------

/// Parse JSON, rejecting duplicate object keys. The bytes forwarded upstream are the bytes the
/// caveats were checked against, so a parser that resolves duplicates differently from
/// `serde_json` (first-wins vs last-wins) must not be able to smuggle a second value.
fn parse_strict_json(bytes: &[u8]) -> std::result::Result<serde_json::Value, String> {
    use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
    use serde_json::Value;

    struct Strict(Value);
    struct V;
    impl<'de> Deserialize<'de> for Strict {
        fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
            d.deserialize_any(V).map(Strict)
        }
    }
    impl<'de> Visitor<'de> for V {
        type Value = Value;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("JSON")
        }
        fn visit_bool<E>(self, v: bool) -> std::result::Result<Value, E> {
            Ok(Value::Bool(v))
        }
        fn visit_i64<E>(self, v: i64) -> std::result::Result<Value, E> {
            Ok(Value::from(v))
        }
        fn visit_u64<E>(self, v: u64) -> std::result::Result<Value, E> {
            Ok(Value::from(v))
        }
        fn visit_f64<E: de::Error>(self, v: f64) -> std::result::Result<Value, E> {
            serde_json::Number::from_f64(v)
                .map(Value::Number)
                .ok_or_else(|| E::custom("non-finite number"))
        }
        fn visit_str<E>(self, v: &str) -> std::result::Result<Value, E> {
            Ok(Value::String(v.to_string()))
        }
        fn visit_unit<E>(self) -> std::result::Result<Value, E> {
            Ok(Value::Null)
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> std::result::Result<Value, A::Error> {
            let mut out = Vec::new();
            while let Some(Strict(v)) = a.next_element()? {
                out.push(v);
            }
            Ok(Value::Array(out))
        }
        fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> std::result::Result<Value, A::Error> {
            let mut seen = HashSet::new();
            let mut out = serde_json::Map::new();
            while let Some(k) = a.next_key::<String>()? {
                if !seen.insert(k.clone()) {
                    return Err(de::Error::custom("duplicate object key"));
                }
                let Strict(v) = a.next_value()?;
                out.insert(k, v);
            }
            Ok(Value::Object(out))
        }
    }
    serde_json::from_slice::<Strict>(bytes)
        .map(|s| s.0)
        .map_err(|e| e.to_string())
}

fn is_json_content_type(ct: &str) -> bool {
    let mt = ct
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    mt == "application/json" || (mt.starts_with("application/") && mt.ends_with("+json"))
}

// ---- request parsing helpers ---------------------------------------------

/// Split the raw request target into `(service, upstream path, query)`. Rejects anything that is
/// not an origin-form path of visible ASCII (so absolute-URL targets and CRLF tricks die here).
fn split_target(target: &str) -> std::result::Result<(&str, String, &str), &'static str> {
    if !target.starts_with('/') {
        return Err("target is not origin-form");
    }
    if !target.bytes().all(|b| (0x21..=0x7e).contains(&b)) || target.contains('#') {
        return Err("illegal characters in target");
    }
    let rest = &target[1..];
    let end = rest.find(['/', '?']).unwrap_or(rest.len());
    let service = &rest[..end];
    if service.is_empty() {
        return Err("empty service");
    }
    let tail = &rest[end..];
    let (path, query) = match tail.split_once('?') {
        Some((p, q)) => (p, q),
        None => (tail, ""),
    };
    let path = if path.is_empty() { "/" } else { path };
    Ok((service, path.to_string(), query))
}

fn bearer_or_token(req: &tiny_http::Request) -> Option<String> {
    let mut found = None;
    for h in req.headers() {
        let name = h.field.as_str().as_str().to_ascii_lowercase();
        let val = h.value.as_str().trim();
        if name == "authorization" {
            let (scheme, tok) = val.split_once(' ')?;
            if scheme.eq_ignore_ascii_case("bearer") {
                found = Some(tok.trim().to_string());
                break;
            }
        } else if name == "x-llms-token" && found.is_none() {
            found = Some(val.to_string());
        }
    }
    found.filter(|t| !t.is_empty())
}

const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Request headers never forwarded: the agent's credentials, hop-by-hop headers, and framing /
/// routing headers the proxy sets itself.
fn drop_request_header(name: &str, extra_connection: &HashSet<String>, inject: &Inject) -> bool {
    let n = name.to_ascii_lowercase();
    HOP_BY_HOP.contains(&n.as_str())
        || n.starts_with("proxy-")
        || extra_connection.contains(&n)
        || matches!(
            n.as_str(),
            "authorization"
                | "cookie"
                | "cookie2"
                | "x-llms-token"
                | "host"
                | "content-length"
                | "expect"
        )
        || matches!(inject, Inject::Header(h) if h.eq_ignore_ascii_case(&n))
}

fn visible_ascii(s: &str) -> bool {
    s.bytes().all(|b| b == b'\t' || (0x20..0x7f).contains(&b))
}

// ---- audit ----------------------------------------------------------------

/// Caveat name (or other short reason) from a verification error: never the full message, which
/// can echo request values.
fn failure_name(err: &Error) -> String {
    match err {
        Error::PolicyDenied { reason, .. } => reason
            .strip_prefix("caveat failed: ")
            .and_then(|r| r.split(':').next())
            .filter(|n| n.chars().all(|c| c.is_ascii_lowercase() || c == '_'))
            .unwrap_or("policy")
            .to_string(),
        Error::NoSession => "revoked_or_no_root_key".into(),
        _ => "signature_invalid".into(),
    }
}

struct Trace {
    service: String,
    method: String,
    host: String,
    path: String,
}

fn audit(ctx: &Context, trace: &Trace, decision: &str, reason: &str) -> Result<()> {
    // Query strings and bodies are never recorded. The path is only recorded once it has passed
    // validation (and is capped), so attacker bytes cannot bloat or forge log lines.
    let path: String = trace.path.chars().take(200).collect();
    let mut note = format!(
        "service={} method={} host={} path={} decision={decision}",
        trace.service, trace.method, trace.host, path
    );
    if !reason.is_empty() {
        note.push_str(&format!(" failed={reason}"));
    }
    crate::lease::record(&format!("proxy.{decision}"), ctx, Some(note))
}

// ---- server ---------------------------------------------------------------

struct Denial {
    status: u16,
    reason: String,
}

fn deny(status: u16, reason: impl Into<String>) -> Denial {
    Denial {
        status,
        reason: reason.into(),
    }
}

struct Upstream {
    status: u16,
    headers: Vec<(String, Vec<u8>)>,
    body: Vec<u8>,
}

pub struct State {
    cfg: ProxyConfig,
    agent: ureq::Agent,
    in_flight: AtomicUsize,
}

impl State {
    pub fn new(cfg: ProxyConfig) -> Self {
        let config = ureq::Agent::config_builder()
            // A redirect must never carry the credential to another host: do not follow, and
            // hand the 3xx back untouched.
            .max_redirects(0)
            .max_redirects_will_error(false)
            .http_status_as_error(false)
            .timeout_connect(Some(cfg.connect_timeout))
            .timeout_global(Some(cfg.timeout))
            .build();
        Self {
            cfg,
            agent: config.into(),
            in_flight: AtomicUsize::new(0),
        }
    }
}

fn generic_body(status: u16) -> &'static str {
    match status {
        400 => "bad request\n",
        403 => "forbidden\n",
        404 => "unknown service\n",
        405 => "method not allowed\n",
        413 => "payload too large\n",
        503 => "busy\n",
        504 => "gateway timeout\n",
        _ => "bad gateway\n",
    }
}

fn respond_denial(req: tiny_http::Request, status: u16) {
    let body = generic_body(status);
    let resp = tiny_http::Response::from_string(body)
        .with_status_code(status)
        .with_header(
            tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"text/plain"[..]).unwrap(),
        );
    let _ = req.respond(resp);
}

fn handle(state: &State, mut req: tiny_http::Request) {
    let target = req.url().to_string();
    let method = req.method().as_str().to_ascii_uppercase();

    let (service_name, path, query) = match split_target(&target) {
        Ok(t) => (t.0.to_string(), t.1, t.2.to_string()),
        Err(why) => {
            let ctx = Context::current("(none)");
            let t = Trace {
                service: "(none)".into(),
                method,
                host: "-".into(),
                path: "(invalid)".into(),
            };
            let _ = audit(&ctx, &t, "deny", why_name(why));
            return respond_denial(req, 400);
        }
    };
    let Some(service) = state.cfg.services.get(&service_name) else {
        let ctx = Context::current("(none)");
        let t = Trace {
            service: "(unknown)".into(),
            method,
            host: "-".into(),
            path: "-".into(),
        };
        let _ = audit(&ctx, &t, "deny", "unknown_service");
        return respond_denial(req, 404);
    };

    let base_ctx = Context::current(&service.secret);
    let mut trace = Trace {
        service: service.name.clone(),
        method: method.clone(),
        host: service.host.clone(),
        path: path.clone(),
    };
    match process(
        state, service, &base_ctx, &mut trace, &mut req, &path, &query,
    ) {
        Ok(up) => {
            let mut headers = Vec::new();
            for (n, v) in up.headers {
                if let Ok(h) = tiny_http::Header::from_bytes(n.as_bytes(), v.as_slice()) {
                    headers.push(h);
                }
            }
            let len = up.body.len();
            let resp = tiny_http::Response::new(
                tiny_http::StatusCode(up.status),
                headers,
                Cursor::new(up.body),
                Some(len),
                None,
            );
            let _ = req.respond(resp);
        }
        Err(d) => {
            let _ = audit(&base_ctx, &trace, "deny", &d.reason);
            respond_denial(req, d.status);
        }
    }
}

fn why_name(why: &str) -> &'static str {
    match why {
        "target is not origin-form" => "bad_target_form",
        "illegal characters in target" => "bad_target_chars",
        _ => "bad_target",
    }
}

fn process(
    state: &State,
    svc: &Service,
    base_ctx: &Context,
    trace: &mut Trace,
    req: &mut tiny_http::Request,
    path: &str,
    query: &str,
) -> std::result::Result<Upstream, Denial> {
    use tiny_http::Method;
    let method = match req.method() {
        Method::Get
        | Method::Head
        | Method::Post
        | Method::Put
        | Method::Patch
        | Method::Delete
        | Method::Options => req.method().as_str().to_ascii_uppercase(),
        _ => return Err(deny(405, "method")),
    };

    // 1. Request context. Anything ambiguous in the path is refused here (400).
    let rc = RequestCtx::new(&svc.host, &method, path, None).map_err(|_| deny(400, "bad_path"))?;

    // 2. Token. Missing or garbled: 403 before we read any body.
    let tok = bearer_or_token(req).ok_or_else(|| deny(403, "no_token"))?;
    let mac = Macaroon::decode(&tok).map_err(|_| deny(403, "token_garbled"))?;
    if !mac
        .caveats
        .iter()
        .any(|c| matches!(c, Caveat::SecretEq(_) | Caveat::SecretsIn(_)))
    {
        return Err(deny(403, "no_secret_caveat"));
    }
    crate::policy::check_access(base_ctx).map_err(|_| deny(403, "policy"))?;

    // 3. Body: capped; parsed as JSON only for a JSON content type, otherwise caveats see None.
    let max = state.cfg.max_body;
    if req.body_length().is_some_and(|n| n > max) {
        return Err(deny(413, "body_size"));
    }
    let mut body = Vec::new();
    req.as_reader()
        .take(max as u64 + 1)
        .read_to_end(&mut body)
        .map_err(|_| deny(400, "body_read"))?;
    if body.len() > max {
        return Err(deny(413, "body_size"));
    }
    let content_type = req
        .headers()
        .iter()
        .find(|h| {
            h.field
                .as_str()
                .as_str()
                .eq_ignore_ascii_case("content-type")
        })
        .map(|h| h.value.as_str().to_string());
    let json = match content_type {
        Some(ct) if is_json_content_type(&ct) && !body.is_empty() => {
            Some(parse_strict_json(&body).map_err(|_| deny(400, "body_json"))?)
        }
        _ => None,
    };

    // 4. Verify against the actual request. Fresh context every time.
    let rc = RequestCtx { body: json, ..rc };
    let ctx = Context {
        key: base_ctx.key,
        now: chrono::Utc::now(),
        who: base_ctx.who.clone(),
        repo: base_ctx.repo.clone(),
        branch: base_ctx.branch.clone(),
        agent: base_ctx.agent.clone(),
        request: Some(rc),
    };
    mac.verify(&ctx).map_err(|e| deny(403, failure_name(&e)))?;

    // 5. Credential from the store (decrypted per request, so rotation takes effect at once).
    let secret = load_secret(&svc.secret).map_err(|_| deny(502, "secret_unavailable"))?;
    let (inject_name, inject_value) = match &svc.inject {
        Inject::Bearer => ("Authorization".to_string(), format!("Bearer {secret}")),
        Inject::Basic => (
            "Authorization".to_string(),
            format!("Basic {}", B64.encode(secret.as_bytes())),
        ),
        Inject::Header(h) => (h.clone(), secret.clone()),
    };
    if secret.is_empty() || !visible_ascii(&inject_value) {
        return Err(deny(502, "credential_unusable"));
    }

    // 6. Audit the allow *before* forwarding, so strict auditing (ADR 0010) fails closed.
    audit(base_ctx, trace, "allow", "").map_err(|_| deny(502, "audit_failed"))?;

    // 7. Forward.
    let scheme = if svc.https { "https" } else { "http" };
    let port = svc.port.map(|p| format!(":{p}")).unwrap_or_default();
    let q = if query.is_empty() {
        String::new()
    } else {
        format!("?{query}")
    };
    let url = format!("{scheme}://{}{port}{}{path}{q}", svc.host, svc.base_path);

    let mut extra_connection = HashSet::new();
    for h in req.headers() {
        if h.field.as_str().as_str().eq_ignore_ascii_case("connection") {
            for t in h.value.as_str().split(',') {
                extra_connection.insert(t.trim().to_ascii_lowercase());
            }
        }
    }
    let mut builder = ureq::http::Request::builder()
        .method(method.as_str())
        .uri(&url);
    for h in req.headers() {
        let name = h.field.as_str().as_str();
        if drop_request_header(name, &extra_connection, &svc.inject) {
            continue;
        }
        builder = builder.header(name, h.value.as_str());
    }
    let out = builder
        .header(inject_name.as_str(), inject_value.as_str())
        .body(body)
        .map_err(|_| deny(400, "request_build"))?;

    let resp = state.agent.run(out).map_err(|e| match e {
        ureq::Error::Timeout(_) => deny(504, "upstream_timeout"),
        _ => deny(502, "upstream_error"),
    })?;
    let (parts, mut rbody) = resp.into_parts();
    let bytes = rbody
        .with_config()
        .limit(MAX_RESPONSE_BODY)
        .read_to_vec()
        .map_err(|_| deny(502, "upstream_body"))?;

    let mut headers = Vec::new();
    for (n, v) in &parts.headers {
        let name = n.as_str();
        let lower = name.to_ascii_lowercase();
        if HOP_BY_HOP.contains(&lower.as_str()) || lower == "content-length" {
            continue;
        }
        // Best effort: drop any response header that visibly echoes the injected credential.
        // Does not catch encoded or transformed echoes, nor an echo in the body.
        let raw = v.as_bytes();
        let echoes = |needle: &str| {
            !needle.is_empty() && raw.windows(needle.len()).any(|w| w == needle.as_bytes())
        };
        if echoes(&secret) || echoes(&inject_value) {
            continue;
        }
        headers.push((name.to_string(), raw.to_vec()));
    }
    Ok(Upstream {
        status: parts.status.as_u16(),
        headers,
        body: bytes,
    })
}

fn load_secret(name: &str) -> Result<String> {
    let identity = crate::store::load_identity()?;
    let store = crate::store::load_store(&identity)?;
    store
        .get(name)
        .map(|s| s.to_string())
        .ok_or_else(|| Error::KeyNotFound(name.to_string()))
}

pub fn run(server: Arc<tiny_http::Server>, state: Arc<State>) {
    for req in server.incoming_requests() {
        if state.in_flight.fetch_add(1, Ordering::SeqCst) >= MAX_IN_FLIGHT {
            state.in_flight.fetch_sub(1, Ordering::SeqCst);
            respond_denial(req, 503);
            continue;
        }
        let st = Arc::clone(&state);
        std::thread::spawn(move || {
            handle(&st, req);
            st.in_flight.fetch_sub(1, Ordering::SeqCst);
        });
    }
}

// ---- CLI entry points -----------------------------------------------------

pub fn serve(
    bind: Option<String>,
    config: Option<PathBuf>,
    allow_non_loopback: bool,
    allow_insecure_upstream: bool,
) -> Result<()> {
    let bind = bind.unwrap_or_else(|| DEFAULT_BIND.to_string());
    let addr: SocketAddr = bind
        .parse()
        .map_err(|_| Error::Other(format!("invalid --bind '{bind}' (expected ADDR:PORT)")))?;
    if !addr.ip().is_loopback() && !allow_non_loopback {
        return Err(Error::Other(format!(
            "refusing to bind non-loopback address {addr}; pass --allow-non-loopback to override (plain HTTP, no TLS)"
        )));
    }
    let cfg = ProxyConfig::load(config, allow_insecure_upstream)?;
    let server = tiny_http::Server::http(addr)
        .map_err(|e| Error::Other(format!("cannot bind {addr}: {e}")))?;
    if !addr.ip().is_loopback() {
        eprintln!(
            "WARNING: proxy bound to non-loopback {addr}: plain HTTP, and anyone who can reach it and holds a valid macaroon can use your credentials"
        );
    }
    if allow_insecure_upstream {
        eprintln!("WARNING: --allow-insecure-upstream permits http:// upstreams (testing only)");
    }
    let bound = server
        .server_addr()
        .to_ip()
        .map(|a| a.to_string())
        .unwrap_or_else(|| addr.to_string());
    println!(
        "llms proxy listening on http://{bound} ({} services)",
        cfg.services.len()
    );
    use std::io::Write as _;
    let _ = std::io::stdout().flush();
    run(Arc::new(server), Arc::new(State::new(cfg)));
    Ok(())
}

pub fn check(service: &str, config: Option<PathBuf>, allow_insecure_upstream: bool) -> Result<()> {
    let cfg = ProxyConfig::load(config, allow_insecure_upstream)?;
    let svc = cfg
        .services
        .get(service)
        .ok_or_else(|| Error::Other(format!("service '{service}' is not in the config")))?;
    let identity = crate::store::load_identity()?;
    let store = crate::store::load_store(&identity)?;
    if !store.contains(&svc.secret) {
        return Err(Error::KeyNotFound(svc.secret.clone()));
    }
    let port = svc.port.map(|p| format!(":{p}")).unwrap_or_default();
    println!(
        "ok: {service} -> {}://{}{port}{} (secret '{}' present, inject {:?})",
        if svc.https { "https" } else { "http" },
        svc.host,
        svc.base_path,
        svc.secret,
        svc.inject
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = r#"
[services.github]
upstream = "https://api.github.com"
secret = "gh"
inject = "bearer"

[services.k]
upstream = "https://example.com:8443/api/"
secret = "k"
inject = "header"
header = "X-Api-Key"
"#;

    #[test]
    fn config_parses() {
        let c = ProxyConfig::parse(GOOD, false).unwrap();
        let g = &c.services["github"];
        assert_eq!(
            (g.host.as_str(), g.port, g.base_path.as_str()),
            ("api.github.com", None, "")
        );
        let k = &c.services["k"];
        assert_eq!((k.port, k.base_path.as_str()), (Some(8443), "/api"));
        assert_eq!(k.inject, Inject::Header("X-Api-Key".into()));
        assert_eq!(c.max_body, DEFAULT_MAX_BODY);
    }

    #[test]
    fn config_rejects_bad_upstreams() {
        for up in [
            "http://api.github.com",
            "https://user@api.github.com",
            "https://api.github.com/x?y=1",
            "https://api.github.com/../x",
            "https://api.github.com//x",
            "https://[::1]/",
            "https://",
            "ftp://x.com",
        ] {
            let t =
                format!("[services.a]\nupstream = \"{up}\"\nsecret = \"s\"\ninject = \"bearer\"\n");
            assert!(ProxyConfig::parse(&t, false).is_err(), "{up}");
        }
        let t = "[services.a]\nupstream = \"http://127.0.0.1:1\"\nsecret = \"s\"\ninject = \"bearer\"\n";
        assert!(ProxyConfig::parse(t, false).is_err());
        assert!(ProxyConfig::parse(t, true).is_ok());
    }

    #[test]
    fn config_rejects_bad_inject_and_names() {
        for bad in [
            "inject = \"header\"",
            "inject = \"bearer\"\nheader = \"X\"",
            "inject = \"header\"\nheader = \"Host\"",
            "inject = \"cookie\"",
        ] {
            let t = format!("[services.a]\nupstream = \"https://x.com\"\nsecret = \"s\"\n{bad}\n");
            assert!(ProxyConfig::parse(&t, false).is_err(), "{bad}");
        }
        let t =
            "[services.A_b]\nupstream = \"https://x.com\"\nsecret = \"s\"\ninject = \"bearer\"\n";
        assert!(ProxyConfig::parse(t, false).is_err());
        assert!(ProxyConfig::parse("bogus = 1", false).is_err());
    }

    #[test]
    fn strict_json_rejects_duplicates_and_trailing() {
        assert!(parse_strict_json(br#"{"a":1,"b":[1,{"c":null}]}"#).is_ok());
        assert!(parse_strict_json(br#"{"a":1,"a":2}"#).is_err());
        assert!(parse_strict_json(br#"{"x":{"a":1,"a":2}}"#).is_err());
        assert!(parse_strict_json(br#"[{"a":1,"a":1}]"#).is_err());
        assert!(parse_strict_json(br#"{"a":1} {"a":2}"#).is_err());
        assert!(parse_strict_json(b"{").is_err());
    }

    #[test]
    fn targets() {
        let ok = split_target("/github/repos/a/b?x=1").unwrap();
        assert_eq!((ok.0, ok.1.as_str(), ok.2), ("github", "/repos/a/b", "x=1"));
        assert_eq!(split_target("/github").unwrap().1, "/");
        assert_eq!(split_target("/github?q").unwrap().1, "/");
        for bad in [
            "http://evil.com/github/x",
            "*",
            "//x",
            "/",
            "/github/a b",
            "/github/a\r\nHost: x",
            "/github/x#frag",
            "/github/\u{e9}",
        ] {
            assert!(split_target(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn content_types() {
        assert!(is_json_content_type("application/json"));
        assert!(is_json_content_type("Application/JSON; charset=utf-8"));
        assert!(is_json_content_type("application/vnd.api+json"));
        assert!(!is_json_content_type("text/plain"));
        assert!(!is_json_content_type("application/x-www-form-urlencoded"));
    }

    #[test]
    fn header_filter() {
        let none = HashSet::new();
        let b = Inject::Bearer;
        for n in [
            "Authorization",
            "cookie",
            "X-Llms-Token",
            "Proxy-Foo",
            "Connection",
            "Host",
            "Transfer-Encoding",
        ] {
            assert!(drop_request_header(n, &none, &b), "{n}");
        }
        assert!(!drop_request_header("Accept", &none, &b));
        let h = Inject::Header("X-Api-Key".into());
        assert!(drop_request_header("x-api-key", &none, &h));
        assert!(!drop_request_header("x-api-key", &none, &b));
        let extra: HashSet<String> = ["x-custom".to_string()].into();
        assert!(drop_request_header("X-Custom", &extra, &b));
    }
}
