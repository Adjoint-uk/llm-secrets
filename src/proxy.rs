//! `llms proxy` — a local credential proxy (route mode). See ADR 0011 and
//! `docs/request-scoped-caveats.md`.
//!
//! The agent calls `http://127.0.0.1:PORT/<service>/<upstream path>` carrying only a macaroon.
//! For every request the proxy builds a [`RequestCtx`] from what it is *actually about to send*
//! (the host comes from config, never from the request), verifies the macaroon against it, swaps
//! in the real credential from the store, forwards, and audits. The agent never holds the secret.
//!
//! Stance: the agent is hostile. Every request field is untrusted and every ambiguity is
//! refused rather than interpreted. Anything that goes wrong before the upstream call yields a
//! generic response and no upstream call; the reason goes to the audit log only.

use std::collections::BTreeMap;
use std::io::{Cursor, Read};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use chrono::Utc;
use serde::Deserialize;
use serde::de::{self, Deserializer, MapAccess, SeqAccess, Visitor};
use tiny_http::{Header, Request, Response, Server, StatusCode};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::lease;
use crate::macaroon::{Caveat, Context, Macaroon, RequestCtx};
use crate::store;

pub const DEFAULT_BIND: &str = "127.0.0.1:8787";
const DEFAULT_MAX_BODY: usize = 1 << 20; // 1 MiB
const DEFAULT_MAX_RESPONSE: usize = 16 << 20; // 16 MiB
const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 5;
const DEFAULT_TIMEOUT_SECS: u64 = 30;
const MAX_IN_FLIGHT: usize = 32;
const MAX_TARGET_LEN: usize = 8192;
/// Below this length a credential is not treated as "echoed" in a response header: a short
/// value would match unrelated headers.
const MIN_ECHO_LEN: usize = 8;

// ---- config ---------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigToml {
    max_body_bytes: Option<usize>,
    max_response_bytes: Option<usize>,
    connect_timeout_secs: Option<u64>,
    timeout_secs: Option<u64>,
    #[serde(default)]
    services: BTreeMap<String, ServiceToml>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceToml {
    upstream: String,
    secret: String,
    inject: String,
    header: Option<String>,
}

/// How the real credential is attached to the upstream request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Inject {
    /// `Authorization: Bearer <secret>`
    Bearer,
    /// `Authorization: Basic base64(<secret>)`; the secret is stored as `user:password`.
    Basic,
    /// `<Name>: <secret>`
    Header(String),
}

#[derive(Debug, Clone)]
pub struct Service {
    pub name: String,
    /// `false` = https (the only form allowed by default). `true` only for a loopback upstream
    /// with `--allow-loopback-http` (local development and tests).
    plain_http: bool,
    pub host: String,
    port: Option<u16>,
    /// Path prefix from the upstream URL (no trailing slash, possibly empty).
    prefix: String,
    pub secret: String,
    pub inject: Inject,
}

impl Service {
    fn origin(&self) -> String {
        let scheme = if self.plain_http { "http" } else { "https" };
        match self.port {
            Some(p) => format!("{scheme}://{}:{p}", self.host),
            None => format!("{scheme}://{}", self.host),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    max_body: usize,
    max_response: usize,
    connect_timeout: Duration,
    timeout: Duration,
    pub services: BTreeMap<String, Service>,
}

impl Config {
    /// Default location: `proxy.toml` next to `profiles.toml` in the llms config dir.
    pub fn default_path() -> Result<PathBuf> {
        Ok(crate::profile::config_dir()?.join("proxy.toml"))
    }

    pub fn load(path: Option<&Path>, allow_loopback_http: bool) -> Result<Self> {
        let path = match path {
            Some(p) => p.to_path_buf(),
            None => Self::default_path()?,
        };
        let text = std::fs::read_to_string(&path).map_err(|e| {
            Error::Other(format!(
                "cannot read proxy config {}: {e} (see docs/PROXY.md for the format)",
                path.display()
            ))
        })?;
        Self::parse(&text, allow_loopback_http)
            .map_err(|e| Error::Other(format!("{}: {e}", path.display())))
    }

    pub fn parse(text: &str, allow_loopback_http: bool) -> std::result::Result<Self, String> {
        let raw: ConfigToml = toml::from_str(text).map_err(|e| format!("invalid config: {e}"))?;

        let max_body = bounded(
            "max_body_bytes",
            raw.max_body_bytes.unwrap_or(DEFAULT_MAX_BODY),
            1,
            64 << 20,
        )?;
        let max_response = bounded(
            "max_response_bytes",
            raw.max_response_bytes.unwrap_or(DEFAULT_MAX_RESPONSE),
            1,
            256 << 20,
        )?;
        let connect = bounded(
            "connect_timeout_secs",
            raw.connect_timeout_secs
                .unwrap_or(DEFAULT_CONNECT_TIMEOUT_SECS) as usize,
            1,
            600,
        )?;
        let total = bounded(
            "timeout_secs",
            raw.timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS) as usize,
            1,
            600,
        )?;

        let mut services = BTreeMap::new();
        for (name, s) in raw.services {
            if !valid_service_name(&name) {
                return Err(format!(
                    "service name '{name}' must be 1-32 chars of a-z, 0-9, '_' or '-'"
                ));
            }
            let svc = parse_service(&name, s, allow_loopback_http)
                .map_err(|e| format!("service '{name}': {e}"))?;
            services.insert(name, svc);
        }
        Ok(Self {
            max_body,
            max_response,
            connect_timeout: Duration::from_secs(connect as u64),
            timeout: Duration::from_secs(total as u64),
            services,
        })
    }
}

fn bounded(name: &str, v: usize, min: usize, max: usize) -> std::result::Result<usize, String> {
    if (min..=max).contains(&v) {
        Ok(v)
    } else {
        Err(format!("{name} must be between {min} and {max}"))
    }
}

fn valid_service_name(s: &str) -> bool {
    (1..=32).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

fn parse_service(
    name: &str,
    s: ServiceToml,
    allow_loopback_http: bool,
) -> std::result::Result<Service, String> {
    if s.secret.trim().is_empty() {
        return Err("secret must name a secret in the store".into());
    }
    let inject = match (s.inject.as_str(), s.header) {
        ("bearer", None) => Inject::Bearer,
        ("basic", None) => Inject::Basic,
        ("bearer" | "basic", Some(_)) => {
            return Err("'header' is only valid with inject = \"header\"".into());
        }
        ("header", Some(h)) => {
            if !valid_header_name(&h) {
                return Err(format!("invalid header name '{h}'"));
            }
            Inject::Header(h)
        }
        ("header", None) => return Err("inject = \"header\" requires a 'header' name".into()),
        (other, _) => {
            return Err(format!(
                "unknown inject '{other}' (expected bearer, basic or header)"
            ));
        }
    };
    let (plain_http, host, port, prefix) = parse_upstream(&s.upstream, allow_loopback_http)?;
    Ok(Service {
        name: name.to_string(),
        plain_http,
        host,
        port,
        prefix,
        secret: s.secret,
        inject,
    })
}

/// Header names that carry framing or routing meaning must never be the injection target.
fn valid_header_name(h: &str) -> bool {
    const FORBIDDEN: &[&str] = &[
        "host",
        "content-length",
        "content-type",
        "transfer-encoding",
        "connection",
        "upgrade",
        "te",
        "trailer",
        "cookie",
        "expect",
    ];
    !h.is_empty()
        && h.len() <= 64
        && h.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && !FORBIDDEN.contains(&h.to_ascii_lowercase().as_str())
        && !h.to_ascii_lowercase().starts_with("proxy-")
}

/// Parse the fixed upstream. https only; `http://` is accepted solely for a loopback host and
/// only when the operator passed `--allow-loopback-http`. No userinfo, query or fragment.
fn parse_upstream(
    url: &str,
    allow_loopback_http: bool,
) -> std::result::Result<(bool, String, Option<u16>, String), String> {
    let (plain_http, rest) = if let Some(r) = url.strip_prefix("https://") {
        (false, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (true, r)
    } else {
        return Err("upstream must start with https://".into());
    };
    if rest
        .bytes()
        .any(|b| !(0x21..=0x7e).contains(&b) || b == b'@' || b == b'?' || b == b'#' || b == b'\\')
    {
        return Err("upstream must not contain userinfo, query, fragment or odd characters".into());
    }
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    let (host, port) = match authority.split_once(':') {
        Some((h, p)) => {
            let port: u16 = p.parse().map_err(|_| "invalid port".to_string())?;
            if port == 0 {
                return Err("invalid port".into());
            }
            (h, Some(port))
        }
        None => (authority, None),
    };
    let host = host.to_ascii_lowercase();
    let prefix = path.trim_end_matches('/').to_string();
    // Reuse the request validator so the host and path prefix obey exactly the rules every
    // proxied request is held to.
    RequestCtx::new(
        &host,
        "GET",
        if prefix.is_empty() { "/" } else { &prefix },
        None,
    )
    .map_err(|e| format!("invalid upstream: {e}"))?;
    if plain_http {
        if !allow_loopback_http {
            return Err("upstream must start with https://".into());
        }
        if !is_loopback_host(&host) {
            return Err("http:// upstreams are only allowed for loopback hosts".into());
        }
    }
    Ok((plain_http, host, port, prefix))
}

fn is_loopback_host(host: &str) -> bool {
    host == "localhost"
        || host
            .parse::<Ipv4Addr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false)
}

// ---- strict JSON ----------------------------------------------------------

/// JSON value that refuses duplicate object keys. A body such as
/// `{"private":true,"private":false}` is read differently by different parsers (first wins vs
/// last wins), so a check on the parsed value would not describe what the upstream acts on.
struct Strict(serde_json::Value);

impl<'de> de::Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        d.deserialize_any(StrictVisitor)
    }
}

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = Strict;

    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("a JSON value")
    }
    fn visit_bool<E>(self, v: bool) -> std::result::Result<Strict, E> {
        Ok(Strict(v.into()))
    }
    fn visit_i64<E>(self, v: i64) -> std::result::Result<Strict, E> {
        Ok(Strict(v.into()))
    }
    fn visit_u64<E>(self, v: u64) -> std::result::Result<Strict, E> {
        Ok(Strict(v.into()))
    }
    fn visit_f64<E: de::Error>(self, v: f64) -> std::result::Result<Strict, E> {
        serde_json::Number::from_f64(v)
            .map(|n| Strict(serde_json::Value::Number(n)))
            .ok_or_else(|| E::custom("non-finite number"))
    }
    fn visit_str<E>(self, v: &str) -> std::result::Result<Strict, E> {
        Ok(Strict(v.into()))
    }
    fn visit_string<E>(self, v: String) -> std::result::Result<Strict, E> {
        Ok(Strict(v.into()))
    }
    fn visit_unit<E>(self) -> std::result::Result<Strict, E> {
        Ok(Strict(serde_json::Value::Null))
    }
    fn visit_none<E>(self) -> std::result::Result<Strict, E> {
        Ok(Strict(serde_json::Value::Null))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> std::result::Result<Strict, A::Error> {
        let mut out = Vec::new();
        while let Some(Strict(v)) = seq.next_element()? {
            out.push(v);
        }
        Ok(Strict(serde_json::Value::Array(out)))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<Strict, A::Error> {
        let mut out = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if out.contains_key(&key) {
                return Err(de::Error::custom("duplicate object key"));
            }
            let Strict(v) = map.next_value()?;
            out.insert(key, v);
        }
        Ok(Strict(serde_json::Value::Object(out)))
    }
}

fn parse_strict_json(bytes: &[u8]) -> std::result::Result<serde_json::Value, String> {
    serde_json::from_slice::<Strict>(bytes)
        .map(|s| s.0)
        .map_err(|e| e.to_string())
}

// ---- request target handling ----------------------------------------------

/// The agent-supplied request target, validated and split into the route parts.
#[derive(Debug, PartialEq, Eq)]
struct Route<'a> {
    service: &'a str,
    /// Upstream path, always starting with `/`.
    path: &'a str,
    query: Option<&'a str>,
}

/// Validate and split `/<service>/<upstream path>[?query]`.
///
/// Anything that is not a plain origin-form path is refused: absolute URLs (`http://host/..`),
/// protocol-relative `//host`, whitespace, control or non-ASCII bytes, fragments, backslashes
/// and malformed percent-escapes. Path-level ambiguity (`..`, encoded slashes, `//`) is refused
/// afterwards by `RequestCtx::new` so the same rules apply to the verified and forwarded path.
fn split_route(target: &str) -> std::result::Result<Route<'_>, &'static str> {
    if target.len() > MAX_TARGET_LEN {
        return Err("target_too_long");
    }
    if !target.starts_with('/') || target.starts_with("//") {
        return Err("not_origin_form");
    }
    if target
        .bytes()
        .any(|b| !(0x21..=0x7e).contains(&b) || b == b'#' || b == b'\\')
    {
        return Err("bad_characters");
    }
    let bytes = target.as_bytes();
    for (i, b) in bytes.iter().enumerate() {
        if *b == b'%'
            && !(bytes.get(i + 1).is_some_and(u8::is_ascii_hexdigit)
                && bytes.get(i + 2).is_some_and(u8::is_ascii_hexdigit))
        {
            return Err("bad_percent_escape");
        }
    }
    let (path_part, query) = match target.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (target, None),
    };
    let after = &path_part[1..];
    let (service, path) = match after.find('/') {
        Some(i) => (&after[..i], &after[i..]),
        None => (after, "/"),
    };
    if service.is_empty() {
        return Err("no_service");
    }
    Ok(Route {
        service,
        path,
        query,
    })
}

fn is_json_content_type(ct: &str) -> bool {
    let mime = ct.split(';').next().unwrap_or("").trim();
    mime.eq_ignore_ascii_case("application/json")
        || mime
            .rsplit_once('+')
            .is_some_and(|(_, s)| s.eq_ignore_ascii_case("json"))
}

/// Methods the proxy will forward. Everything else (CONNECT, TRACE, custom verbs) is refused.
fn allowed_method(m: &str) -> bool {
    matches!(
        m,
        "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS"
    )
}

/// Request headers that are never forwarded: credentials the agent holds, framing and
/// hop-by-hop headers, anything that could redirect the request to another host, and the
/// method-override headers that would let a permitted method act as a forbidden one.
fn drop_request_header(lower: &str, inject_header: Option<&str>) -> bool {
    matches!(
        lower,
        "authorization"
            | "cookie"
            | "x-llms-token"
            | "host"
            | "connection"
            | "keep-alive"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "content-length"
            | "expect"
            | "forwarded"
            | "via"
            | "x-http-method-override"
            | "x-method-override"
            | "x-http-method"
            | "x-original-url"
            | "x-rewrite-url"
    ) || lower.starts_with("proxy-")
        || lower.starts_with("x-forwarded-")
        || inject_header.is_some_and(|h| h.eq_ignore_ascii_case(lower))
}

/// Hop-by-hop response headers. `content-length` is recomputed from the buffered body.
fn drop_response_header(lower: &str) -> bool {
    matches!(
        lower,
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
            | "content-length"
    )
}

/// Pull the macaroon from `Authorization: Bearer <m>` or, failing that, `X-Llms-Token`.
fn extract_token(headers: &[(String, String)]) -> Option<String> {
    let bearer = headers.iter().find_map(|(k, v)| {
        if k == "authorization" {
            let (scheme, rest) = v.split_once(' ')?;
            scheme
                .eq_ignore_ascii_case("bearer")
                .then(|| rest.trim().to_string())
        } else {
            None
        }
    });
    bearer
        .or_else(|| {
            headers
                .iter()
                .find(|(k, _)| k == "x-llms-token")
                .map(|(_, v)| v.trim().to_string())
        })
        .filter(|t| !t.is_empty())
}

/// Name of the caveat in a `caveat failed: <name>: ...` denial. Only the name is audited: the
/// remainder can carry request values.
fn failing_caveat(err: &Error) -> String {
    match err {
        Error::PolicyDenied { reason, .. } => {
            let r = reason.strip_prefix("caveat failed: ").unwrap_or(reason);
            let name = r.split(':').next().unwrap_or("caveat");
            format!("caveat:{name}")
        }
        Error::Other(m) if m.contains("signature invalid") => "signature".to_string(),
        _ => "verify_error".to_string(),
    }
}

/// A token must narrow to the service's secret; a bare root/session macaroon is not accepted.
fn scoped_to_secret(m: &Macaroon, secret: &str) -> bool {
    m.caveats.iter().any(|c| match c {
        Caveat::SecretEq(s) => s == secret,
        Caveat::SecretsIn(list) => list.iter().any(|s| s == secret),
        _ => false,
    })
}

// ---- server ---------------------------------------------------------------

struct EnvCtx {
    who: String,
    repo: String,
    branch: String,
    agent: String,
}

struct State {
    config: Config,
    env: EnvCtx,
    http: ureq::Agent,
    in_flight: AtomicUsize,
}

struct InFlight<'a>(&'a AtomicUsize);
impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Everything audited about a request, filled in as parsing progresses. Never holds a token,
/// credential, header value or body.
struct Trace {
    service: String,
    secret: String,
    method: String,
    host: String,
    path: String,
}

impl Trace {
    fn new() -> Self {
        let dash = || "-".to_string();
        Self {
            service: dash(),
            secret: dash(),
            method: dash(),
            host: dash(),
            path: dash(),
        }
    }

    fn note(&self, decision: &str, reason: Option<&str>) -> String {
        let mut s = format!(
            "service={} method={} host={} path={} decision={decision}",
            self.service, self.method, self.host, self.path
        );
        if let Some(r) = reason {
            s.push_str(&format!(" reason={r}"));
        }
        s
    }
}

struct Deny {
    status: u16,
    reason: String,
}

fn deny(status: u16, reason: impl Into<String>) -> Deny {
    Deny {
        status,
        reason: reason.into(),
    }
}

struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Reply {
    /// Generic body for every refusal; the reason only goes to the audit log.
    fn generic(status: u16) -> Self {
        let text = match status {
            400 => "bad request\n",
            403 => "forbidden\n",
            404 => "not found\n",
            405 => "method not allowed\n",
            413 => "payload too large\n",
            503 => "unavailable\n",
            _ => "bad gateway\n",
        };
        Self {
            status,
            headers: vec![("Content-Type".into(), "text/plain; charset=utf-8".into())],
            body: text.as_bytes().to_vec(),
        }
    }
}

/// `true` for an address that only the local machine can reach.
fn is_loopback_addr(addr: &SocketAddr) -> bool {
    match addr.ip() {
        IpAddr::V4(ip) => ip.is_loopback(),
        IpAddr::V6(ip) => ip.to_canonical().is_loopback(),
    }
}

/// Parse and police the bind address. Loopback by default; anything else needs an explicit flag.
pub fn check_bind(bind: &str, allow_non_loopback: bool) -> Result<SocketAddr> {
    let addr: SocketAddr = bind.parse().map_err(|_| {
        Error::Other(format!(
            "invalid --bind '{bind}': expected IP:PORT such as 127.0.0.1:8787"
        ))
    })?;
    if !is_loopback_addr(&addr) && !allow_non_loopback {
        return Err(Error::Other(format!(
            "refusing to bind {addr}: not a loopback address. The proxy holds your secrets and has no \
             authentication of its own beyond the macaroon; pass --allow-non-loopback to override"
        )));
    }
    Ok(addr)
}

pub fn serve(
    bind: &str,
    config_path: Option<&Path>,
    allow_non_loopback: bool,
    allow_loopback_http: bool,
) -> Result<()> {
    let addr = check_bind(bind, allow_non_loopback)?;
    let config = Config::load(config_path, allow_loopback_http)?;
    if config.services.is_empty() {
        return Err(Error::Other(
            "proxy config defines no services (add a [services.<name>] table)".into(),
        ));
    }
    if !is_loopback_addr(&addr) {
        eprintln!(
            "warning: proxy bound to non-loopback address {addr}. Anything that can reach it can \
             present a macaroon; there is no TLS. Use only on a trusted network."
        );
    }
    if config.services.values().any(|s| s.plain_http) {
        eprintln!(
            "warning: --allow-loopback-http is set; credentials are sent in clear text to loopback upstreams."
        );
    }

    // Environment-derived caveats (repo, branch, agent, user) are evaluated against the proxy's
    // own environment, not the caller's, so compute them once instead of shelling out to git on
    // every request. `now` is refreshed per request.
    let base = Context::current("-");
    let env = EnvCtx {
        who: base.who,
        repo: base.repo,
        branch: base.branch,
        agent: base.agent,
    };
    let http = ureq::AgentBuilder::new()
        .redirects(0) // never follow: a redirect must not carry the credential to another host
        .timeout_connect(config.connect_timeout)
        .timeout(config.timeout)
        .build();
    let names: Vec<String> = config.services.keys().cloned().collect();
    let state = Arc::new(State {
        config,
        env,
        http,
        in_flight: AtomicUsize::new(0),
    });

    let server =
        Server::http(addr).map_err(|e| Error::Other(format!("cannot listen on {addr}: {e}")))?;
    let bound = server
        .server_addr()
        .to_ip()
        .ok_or_else(|| Error::Other("proxy bound to a non-IP address".into()))?;
    println!("listening on {bound} (services: {})", names.join(", "));
    use std::io::Write;
    let _ = std::io::stdout().flush();

    for request in server.incoming_requests() {
        if state.in_flight.fetch_add(1, Ordering::SeqCst) >= MAX_IN_FLIGHT {
            state.in_flight.fetch_sub(1, Ordering::SeqCst);
            send(request, Reply::generic(503));
            continue;
        }
        let st = Arc::clone(&state);
        std::thread::spawn(move || {
            let _guard = InFlight(&st.in_flight);
            handle(&st, request);
        });
    }
    Ok(())
}

fn send(request: Request, reply: Reply) {
    let headers: Vec<Header> = reply
        .headers
        .iter()
        .filter_map(|(k, v)| Header::from_bytes(k.as_bytes(), v.as_bytes()).ok())
        .collect();
    let len = reply.body.len();
    let response = Response::new(
        StatusCode(reply.status),
        headers,
        Cursor::new(reply.body),
        Some(len),
        None,
    );
    let _ = request.respond(response);
}

fn audit_ctx<'a>(state: &State, key: &'a str) -> Context<'a> {
    Context {
        key,
        now: Utc::now(),
        who: state.env.who.clone(),
        repo: state.env.repo.clone(),
        branch: state.env.branch.clone(),
        agent: state.env.agent.clone(),
        request: None,
    }
}

fn handle(state: &State, mut request: Request) {
    let mut trace = Trace::new();
    match process(state, &mut request, &mut trace) {
        Ok(reply) => send(request, reply),
        Err(d) => {
            // Denials are best-effort audited even in strict mode: the request is refused anyway.
            let ctx = audit_ctx(state, &trace.secret);
            let _ = lease::record(
                "proxy.request",
                &ctx,
                Some(trace.note("deny", Some(&d.reason))),
            );
            send(request, Reply::generic(d.status));
        }
    }
}

fn process(
    state: &State,
    request: &mut Request,
    trace: &mut Trace,
) -> std::result::Result<Reply, Deny> {
    // 1. Method.
    let method = request.method().as_str().to_ascii_uppercase();
    if !allowed_method(&method) {
        return Err(deny(405, "method_not_allowed"));
    }
    trace.method = method.clone();

    // 2. Route. The upstream host is whatever the config says for the named service, never
    //    anything taken from the request.
    let target = request.url().to_string();
    let route = split_route(&target).map_err(|r| deny(400, r))?;
    let svc = state
        .config
        .services
        .get(route.service)
        .ok_or_else(|| deny(404, "unknown_service"))?;
    trace.service = svc.name.clone();
    trace.secret = svc.secret.clone();
    trace.host = svc.host.clone();

    // 3. Headers (lower-cased names), then the body, capped.
    let headers: Vec<(String, String)> = request
        .headers()
        .iter()
        .map(|h| {
            (
                h.field.to_string().to_ascii_lowercase(),
                h.value.to_string(),
            )
        })
        .collect();
    let max = state.config.max_body;
    if request.body_length().is_some_and(|n| n > max) {
        return Err(deny(413, "body_too_large"));
    }
    let mut body = Vec::new();
    request
        .as_reader()
        .take(max as u64 + 1)
        .read_to_end(&mut body)
        .map_err(|_| deny(400, "body_read_failed"))?;
    if body.len() > max {
        return Err(deny(413, "body_too_large"));
    }

    // 4. Body for the caveats: parsed only when declared JSON, otherwise absent so any body
    //    caveat fails closed. Declared JSON that does not parse strictly is refused outright.
    let json_declared = headers
        .iter()
        .find(|(k, _)| k == "content-type")
        .is_some_and(|(_, v)| is_json_content_type(v));
    let json_body = if json_declared && !body.is_empty() {
        Some(parse_strict_json(&body).map_err(|_| deny(400, "bad_json"))?)
    } else {
        None
    };

    // 5. The request as it will actually be sent: configured host, upstream path including any
    //    configured prefix. `RequestCtx::new` refuses ambiguous paths.
    let full_path = format!("{}{}", svc.prefix, route.path);
    let rctx = RequestCtx::new(&svc.host, &method, &full_path, json_body)
        .map_err(|_| deny(400, "bad_path"))?;
    trace.path = truncate(&rctx.path, 256);
    let upstream_path = rctx.path.clone();

    // 6. Token.
    let token = extract_token(&headers).ok_or_else(|| deny(403, "no_token"))?;
    let macaroon = Macaroon::decode(&token).map_err(|_| deny(403, "token_invalid"))?;
    if !scoped_to_secret(&macaroon, &svc.secret) {
        return Err(deny(403, "not_scoped_to_secret"));
    }

    // 7. Policy file, then the macaroon itself against the real request.
    let ctx = Context {
        key: &svc.secret,
        now: Utc::now(),
        who: state.env.who.clone(),
        repo: state.env.repo.clone(),
        branch: state.env.branch.clone(),
        agent: state.env.agent.clone(),
        request: Some(rctx),
    };
    crate::policy::check_access(&ctx).map_err(|_| deny(403, "policy"))?;
    macaroon
        .verify(&ctx)
        .map_err(|e| deny(403, failing_caveat(&e)))?;

    // 8. Credential. Decrypted per request, so `revoke-all` and key rotation take effect at
    //    once and nothing long-lived holds plaintext.
    let secret = load_secret(&svc.secret).map_err(|_| deny(502, "secret_unavailable"))?;
    let (cred_name, cred_value) = credential_header(&svc.inject, &secret)
        .ok_or_else(|| deny(502, "credential_not_injectable"))?;

    // 9. Audit the allow *before* forwarding, so strict mode (ADR 0010) can fail closed.
    lease::record("proxy.request", &ctx, Some(trace.note("allow", None)))
        .map_err(|_| deny(503, "audit_failed"))?;

    // 10. Forward.
    let inject_header = match &svc.inject {
        Inject::Header(h) => Some(h.as_str()),
        _ => None,
    };
    let mut url = format!("{}{}", svc.origin(), upstream_path);
    if let Some(q) = route.query {
        url.push('?');
        url.push_str(q);
    }
    let mut up = state.http.request(&method, &url);
    for (k, v) in &headers {
        if !drop_request_header(k, inject_header) {
            up = up.set(k, v);
        }
    }
    up = up.set(&cred_name, &cred_value);

    let result = if body.is_empty() && !matches!(method.as_str(), "POST" | "PUT" | "PATCH") {
        up.call()
    } else {
        up.send_bytes(&body)
    };
    let resp = match result {
        Ok(r) => r,
        Err(ureq::Error::Status(_, r)) => r,
        Err(ureq::Error::Transport(_)) => return Err(deny(502, "upstream_error")),
    };

    // 11. Response: hop-by-hop headers dropped; so is any header that echoes the credential
    //     (best effort: the body is not inspected).
    let status = resp.status();
    let mut out_headers = Vec::new();
    for name in resp.headers_names() {
        let lower = name.to_ascii_lowercase();
        if drop_response_header(&lower) {
            continue;
        }
        for value in resp.all(&name) {
            if echoes(value, &secret, &cred_value) {
                continue;
            }
            out_headers.push((name.clone(), value.to_string()));
        }
    }
    let mut out_body = Vec::new();
    resp.into_reader()
        .take(state.config.max_response as u64 + 1)
        .read_to_end(&mut out_body)
        .map_err(|_| deny(502, "upstream_read_failed"))?;
    if out_body.len() > state.config.max_response {
        return Err(deny(502, "response_too_large"));
    }
    Ok(Reply {
        status,
        headers: out_headers,
        body: out_body,
    })
}

fn truncate(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

fn echoes(header_value: &str, secret: &str, injected: &str) -> bool {
    (secret.len() >= MIN_ECHO_LEN && header_value.contains(secret))
        || (injected.len() >= MIN_ECHO_LEN && header_value.contains(injected))
}

fn load_secret(name: &str) -> Result<Zeroizing<String>> {
    let identity = store::load_identity()?;
    let store = store::load_store(&identity)?;
    store
        .get(name)
        .map(|v| Zeroizing::new(v.to_string()))
        .ok_or_else(|| Error::KeyNotFound(name.to_string()))
}

/// Build the injected header. `None` when the stored value cannot be sent as a header value
/// (control characters, CR/LF), which would otherwise allow header injection.
fn credential_header(inject: &Inject, secret: &str) -> Option<(String, Zeroizing<String>)> {
    let visible = secret.bytes().all(|b| (0x20..=0x7e).contains(&b));
    match inject {
        Inject::Bearer if visible => Some((
            "Authorization".into(),
            Zeroizing::new(format!("Bearer {secret}")),
        )),
        Inject::Basic if !secret.is_empty() => Some((
            "Authorization".into(),
            Zeroizing::new(format!("Basic {}", B64.encode(secret))),
        )),
        Inject::Header(name) if visible => Some((name.clone(), Zeroizing::new(secret.to_string()))),
        _ => None,
    }
}

// ---- `llms proxy check` -----------------------------------------------------

/// Validate the config (and that each referenced secret exists) without serving.
pub fn check(
    service: Option<&str>,
    config_path: Option<&Path>,
    allow_loopback_http: bool,
) -> Result<()> {
    let config = Config::load(config_path, allow_loopback_http)?;
    let selected: Vec<&Service> = match service {
        Some(name) => vec![config.services.get(name).ok_or_else(|| {
            Error::Other(format!(
                "service '{name}' is not defined in the proxy config (defined: {})",
                config
                    .services
                    .keys()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        })?],
        None => config.services.values().collect(),
    };
    if selected.is_empty() {
        return Err(Error::Other("proxy config defines no services".into()));
    }
    let identity = store::load_identity()?;
    let store = store::load_store(&identity)?;
    let mut missing = Vec::new();
    for s in selected {
        let how = match &s.inject {
            Inject::Bearer => "bearer".to_string(),
            Inject::Basic => "basic".to_string(),
            Inject::Header(h) => format!("header {h}"),
        };
        let present = store.contains(&s.secret);
        println!(
            "{}: {}{} -> secret '{}' ({}) [{}]",
            s.name,
            s.origin(),
            s.prefix,
            s.secret,
            how,
            if present { "ok" } else { "MISSING from store" }
        );
        if !present {
            missing.push(s.secret.clone());
        }
    }
    if missing.is_empty() {
        Ok(())
    } else {
        Err(Error::Other(format!(
            "secret(s) not in the store: {}",
            missing.join(", ")
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = r#"
        [services.github]
        upstream = "https://api.github.com"
        secret = "github_token"
        inject = "bearer"
    "#;

    #[test]
    fn parses_a_valid_config() {
        let c = Config::parse(GOOD, false).unwrap();
        let s = &c.services["github"];
        assert_eq!(s.host, "api.github.com");
        assert_eq!(s.origin(), "https://api.github.com");
        assert_eq!(s.inject, Inject::Bearer);
        assert_eq!(c.max_body, DEFAULT_MAX_BODY);
    }

    #[test]
    fn upstream_rules() {
        for bad in [
            "http://api.example.com",       // plain http, not loopback
            "ftp://api.example.com",        // wrong scheme
            "https://user@api.example.com", // userinfo
            "https://api.example.com?x=1",  // query
            "https://api.example.com/a/../b",
            "https://api.example.com//x",
            "https://",
            "api.example.com",
            "https://api.example.com:0",
        ] {
            assert!(parse_upstream(bad, false).is_err(), "{bad} must be refused");
        }
        // http is only for loopback, and only with the flag.
        assert!(parse_upstream("http://127.0.0.1:9000", false).is_err());
        assert!(parse_upstream("http://127.0.0.1:9000", true).is_ok());
        assert!(parse_upstream("http://example.com", true).is_err());
        let (_, host, port, prefix) =
            parse_upstream("https://API.Example.com:8443/v1/", false).unwrap();
        assert_eq!(
            (host.as_str(), port, prefix.as_str()),
            ("api.example.com", Some(8443), "/v1")
        );
    }

    #[test]
    fn inject_modes_validate() {
        let mk = |extra: &str| {
            Config::parse(
                &format!(
                    "[services.a]\nupstream = \"https://x.example.com\"\nsecret = \"s\"\n{extra}"
                ),
                false,
            )
        };
        assert!(mk("inject = \"basic\"").is_ok());
        assert!(mk("inject = \"header\"\nheader = \"x-api-key\"").is_ok());
        assert!(mk("inject = \"header\"").is_err());
        assert!(mk("inject = \"bearer\"\nheader = \"x-api-key\"").is_err());
        assert!(mk("inject = \"header\"\nheader = \"Host\"").is_err());
        assert!(mk("inject = \"header\"\nheader = \"bad name\"").is_err());
        assert!(mk("inject = \"magic\"").is_err());
        assert!(
            Config::parse("bogus = 1", false).is_err(),
            "unknown keys refused"
        );
    }

    #[test]
    fn route_splitting() {
        let r = split_route("/gh/repos/a/b?per_page=5").unwrap();
        assert_eq!(
            (r.service, r.path, r.query),
            ("gh", "/repos/a/b", Some("per_page=5"))
        );
        let r = split_route("/gh").unwrap();
        assert_eq!((r.service, r.path), ("gh", "/"));
        for bad in [
            "http://evil.example/x",
            "//evil.example/x",
            "gh/x",
            "/",
            "/gh/a b",
            "/gh/a#frag",
            "/gh/a\\b",
            "/gh/a%zz",
            "/gh/a%2",
            "/gh/\u{e9}",
            "/gh/\r\nX: y",
        ] {
            assert!(split_route(bad).is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn strict_json_rejects_duplicate_keys() {
        assert!(parse_strict_json(br#"{"a":1,"b":[1,{"c":null}]}"#).is_ok());
        assert!(parse_strict_json(br#"{"a":1,"a":2}"#).is_err());
        assert!(
            parse_strict_json(br#"{"x":{"a":1,"a":2}}"#).is_err(),
            "nested duplicates too"
        );
        assert!(parse_strict_json(br#"[{"a":1,"a":2}]"#).is_err());
        assert!(parse_strict_json(b"{} trailing").is_err());
        assert!(parse_strict_json(b"{not json").is_err());
        // Same value the ordinary parser produces, so caveats see what they expect.
        let v = parse_strict_json(br#"{"private":true,"n":1.5,"s":"x"}"#).unwrap();
        assert_eq!(v, serde_json::json!({"private": true, "n": 1.5, "s": "x"}));
    }

    #[test]
    fn json_content_types() {
        assert!(is_json_content_type("application/json"));
        assert!(is_json_content_type("Application/JSON; charset=utf-8"));
        assert!(is_json_content_type("application/vnd.api+json"));
        assert!(!is_json_content_type("text/plain"));
        assert!(!is_json_content_type("application/jsonx"));
    }

    #[test]
    fn request_header_filtering() {
        for h in [
            "authorization",
            "cookie",
            "x-llms-token",
            "host",
            "proxy-authorization",
            "proxy-connection",
            "transfer-encoding",
            "x-http-method-override",
            "x-forwarded-host",
            "x-original-url",
        ] {
            assert!(drop_request_header(h, None), "{h} must not be forwarded");
        }
        assert!(!drop_request_header("content-type", None));
        assert!(!drop_request_header("accept", None));
        assert!(drop_request_header("x-api-key", Some("X-Api-Key")));
        assert!(!drop_request_header("x-api-key", None));
    }

    #[test]
    fn token_extraction() {
        let h = |pairs: &[(&str, &str)]| -> Vec<(String, String)> {
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect()
        };
        assert_eq!(
            extract_token(&h(&[("authorization", "Bearer abc")])),
            Some("abc".into())
        );
        assert_eq!(
            extract_token(&h(&[("authorization", "bearer  abc ")])),
            Some("abc".into())
        );
        assert_eq!(
            extract_token(&h(&[("x-llms-token", "xyz")])),
            Some("xyz".into())
        );
        // Non-bearer Authorization falls through to X-Llms-Token.
        assert_eq!(
            extract_token(&h(&[
                ("authorization", "Basic zzz"),
                ("x-llms-token", "xyz")
            ])),
            Some("xyz".into())
        );
        assert_eq!(extract_token(&h(&[("authorization", "Basic zzz")])), None);
        assert_eq!(extract_token(&h(&[("authorization", "Bearer ")])), None);
        assert_eq!(extract_token(&h(&[])), None);
    }

    #[test]
    fn bind_policy() {
        assert!(check_bind("127.0.0.1:0", false).is_ok());
        assert!(check_bind("[::1]:0", false).is_ok());
        assert!(check_bind("0.0.0.0:0", false).is_err());
        assert!(check_bind("192.168.1.5:8787", false).is_err());
        assert!(check_bind("[::ffff:192.168.1.5]:8787", false).is_err());
        assert!(check_bind("0.0.0.0:0", true).is_ok());
        assert!(
            check_bind("localhost:8787", false).is_err(),
            "must be an IP:PORT"
        );
    }

    #[test]
    fn credential_headers() {
        let (n, v) = credential_header(&Inject::Bearer, "tok123").unwrap();
        assert_eq!((n.as_str(), v.as_str()), ("Authorization", "Bearer tok123"));
        let (_, v) = credential_header(&Inject::Basic, "user:pw").unwrap();
        assert_eq!(v.as_str(), "Basic dXNlcjpwdw==");
        let (n, v) = credential_header(&Inject::Header("X-Api-Key".into()), "k").unwrap();
        assert_eq!((n.as_str(), v.as_str()), ("X-Api-Key", "k"));
        // A stored value that would split the header is refused, never sent.
        assert!(credential_header(&Inject::Bearer, "a\r\nX-Evil: 1").is_none());
        assert!(credential_header(&Inject::Header("X-Api-Key".into()), "a\nb").is_none());
    }

    #[test]
    fn echo_detection() {
        assert!(echoes(
            "Bearer supersecret1",
            "supersecret1",
            "Bearer supersecret1"
        ));
        assert!(echoes("token=supersecret1;", "supersecret1", "x"));
        assert!(!echoes("text/plain", "supersecret1", "Bearer supersecret1"));
        // Short credentials are not matched, to avoid dropping unrelated headers.
        assert!(!echoes("a", "a", "a"));
    }
}
