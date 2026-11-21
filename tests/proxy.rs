//! Integration tests for `llms proxy` (issue #48).
//!
//! Each test gets its own store and config dir, a fake upstream (a `tiny_http` thread on
//! 127.0.0.1, so no real network), and a real `llms proxy serve` child process. Requests are
//! sent over a raw TCP socket so the test controls the exact bytes: an HTTP client library
//! would normalise `..` and friends away before the proxy ever saw them.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use assert_cmd::Command;
use base64::Engine;
use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64URL};
use tempfile::TempDir;

const SECRET: &str = "REAL-SECRET-VALUE-1234";
const OTHER_SECRET: &str = "other-secret-value-5678";
const BASIC_SECRET: &str = "svcuser:p4ssw0rd-zzz";
const HDR_SECRET: &str = "hdr-secret-value-9999";

/// Variables that make `llms` think it is running under a coding agent.
const AGENT_VARS: &[&str] = &[
    "CLAUDECODE",
    "CLAUDE_CODE",
    "CLAUDE_CODE_ENTRYPOINT",
    "CURSOR_AGENT",
    "CURSOR_TRACE_ID",
    "COPILOT_AGENT_ID",
    "GITHUB_COPILOT_TOKEN",
    "AIDER_CHAT_HISTORY_FILE",
    "AIDER_MODEL",
    "CONTINUE_GLOBAL_DIR",
    "WINDSURF_SESSION_ID",
    "CODEIUM_API_KEY",
    "LLM_SECRETS_MACAROON",
    "LLM_SECRETS_AUDIT_STRICT",
];

// ---- environment ------------------------------------------------------------

struct Env {
    dir: TempDir,
}

impl Env {
    fn new() -> Self {
        let env = Self {
            dir: tempfile::tempdir().unwrap(),
        };
        for d in ["store", "config", "work"] {
            std::fs::create_dir_all(env.dir.path().join(d)).unwrap();
        }
        env.llms().arg("init").assert().success();
        for (name, value) in [
            ("github_token", SECRET),
            ("other_token", OTHER_SECRET),
            ("basic_cred", BASIC_SECRET),
            ("hdr_cred", HDR_SECRET),
        ] {
            env.llms()
                .args(["set", name, "--stdin"])
                .write_stdin(value)
                .assert()
                .success();
        }
        env.session();
        env
    }

    fn session(&self) {
        self.llms()
            .args(["session-start", "--ttl", "1h"])
            .assert()
            .success();
    }

    fn store(&self) -> PathBuf {
        self.dir.path().join("store")
    }
    fn config_dir(&self) -> PathBuf {
        self.dir.path().join("config")
    }
    fn work(&self) -> PathBuf {
        self.dir.path().join("work")
    }
    fn config_path(&self) -> PathBuf {
        self.config_dir().join("proxy.toml")
    }

    fn envs(&self) -> Vec<(&'static str, PathBuf)> {
        vec![
            ("LLM_SECRETS_DIR", self.store()),
            ("LLM_SECRETS_CONFIG_DIR", self.config_dir()),
            ("HOME", self.work()),
            ("XDG_CONFIG_HOME", self.work()),
            ("XDG_DATA_HOME", self.work()),
            // Deterministic git context: not a repo, no user.email.
            ("GIT_CONFIG_GLOBAL", PathBuf::from("/dev/null")),
            ("GIT_CONFIG_NOSYSTEM", PathBuf::from("1")),
        ]
    }

    fn llms(&self) -> Command {
        let mut c = Command::cargo_bin("llms").unwrap();
        c.current_dir(self.work());
        for (k, v) in self.envs() {
            c.env(k, v);
        }
        for k in AGENT_VARS {
            c.env_remove(k);
        }
        c
    }

    fn spawn_proxy(&self, args: &[&str]) -> std::io::Result<Child> {
        let mut c = std::process::Command::new(env!("CARGO_BIN_EXE_llms"));
        c.current_dir(self.work());
        for (k, v) in self.envs() {
            c.env(k, v);
        }
        for k in AGENT_VARS {
            c.env_remove(k);
        }
        c.args(["proxy", "serve"])
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
    }

    /// Write `proxy.toml` with a service per injection mode, all pointing at `upstream`.
    fn write_config(&self, upstream: SocketAddr, globals: &str) {
        let u = format!("http://{upstream}");
        let text = format!(
            r#"{globals}
[services.api]
upstream = "{u}"
secret = "github_token"
inject = "bearer"

[services.basic]
upstream = "{u}"
secret = "basic_cred"
inject = "basic"

[services.hdr]
upstream = "{u}"
secret = "hdr_cred"
inject = "header"
header = "X-Api-Key"
"#
        );
        std::fs::write(self.config_path(), text).unwrap();
    }

    fn mint(&self, args: &[&str]) -> String {
        let out = self
            .llms()
            .args(["macaroon", "mint", "--ttl", "5m"])
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "mint failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap().trim().to_string()
    }

    fn audit_json(&self) -> String {
        let out = self
            .llms()
            .args(["audit", "--json", "--last", "500"])
            .output()
            .unwrap();
        String::from_utf8(out.stdout).unwrap()
    }
}

// ---- fake upstream -----------------------------------------------------------

#[derive(Clone, Debug)]
struct Seen {
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Seen {
    fn header(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
            .collect()
    }
}

struct Upstream {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<Seen>>>,
    /// Requests received by the "other host" a redirect points at.
    other_hits: Arc<AtomicUsize>,
}

impl Upstream {
    fn start() -> Self {
        let other = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let other_addr = other.server_addr().to_ip().unwrap();
        let other_hits = Arc::new(AtomicUsize::new(0));
        let hits = Arc::clone(&other_hits);
        std::thread::spawn(move || {
            for req in other.incoming_requests() {
                hits.fetch_add(1, Ordering::SeqCst);
                let _ = req.respond(tiny_http::Response::from_string("stolen"));
            }
        });

        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let addr = server.server_addr().to_ip().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&seen);
        std::thread::spawn(move || {
            for mut req in server.incoming_requests() {
                let mut body = Vec::new();
                let _ = req.as_reader().read_to_end(&mut body);
                let headers: Vec<(String, String)> = req
                    .headers()
                    .iter()
                    .map(|h| {
                        (
                            h.field.to_string().to_ascii_lowercase(),
                            h.value.to_string(),
                        )
                    })
                    .collect();
                let url = req.url().to_string();
                let auth = headers
                    .iter()
                    .find(|(k, _)| k == "authorization")
                    .map(|(_, v)| v.clone())
                    .unwrap_or_default();
                log.lock().unwrap().push(Seen {
                    method: req.method().as_str().to_string(),
                    url: url.clone(),
                    headers,
                    body,
                });
                let h = |k: &str, v: &str| tiny_http::Header::from_bytes(k, v).unwrap();
                if url.starts_with("/slow") {
                    std::thread::sleep(Duration::from_secs(4));
                }
                let resp = if url.starts_with("/redirect") {
                    tiny_http::Response::from_string("")
                        .with_status_code(302)
                        .with_header(h("Location", &format!("http://{other_addr}/stolen")))
                } else if url.starts_with("/echo") {
                    tiny_http::Response::from_string(r#"{"ok":true}"#)
                        .with_header(h("X-Echo-Auth", &auth))
                        .with_header(h("X-Upstream", "yes"))
                } else {
                    tiny_http::Response::from_string(r#"{"ok":true}"#)
                        .with_header(h("Content-Type", "application/json"))
                        .with_header(h("X-Upstream", "yes"))
                };
                let _ = req.respond(resp);
            }
        });
        Self {
            addr,
            seen,
            other_hits,
        }
    }

    fn hits(&self) -> usize {
        self.seen.lock().unwrap().len()
    }
    fn last(&self) -> Seen {
        self.seen
            .lock()
            .unwrap()
            .last()
            .cloned()
            .expect("no request reached the upstream")
    }
}

// ---- proxy process + raw HTTP --------------------------------------------------

struct Proxy {
    child: Child,
    addr: SocketAddr,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start_proxy(env: &Env, extra: &[&str]) -> Proxy {
    let mut args = vec!["--bind", "127.0.0.1:0", "--allow-loopback-http"];
    args.extend_from_slice(extra);
    let mut child = env.spawn_proxy(&args).expect("spawn llms proxy");
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    if line.is_empty() {
        let mut err = String::new();
        child.stderr.take().unwrap().read_to_string(&mut err).ok();
        panic!("proxy exited before listening: {err}");
    }
    let addr = line
        .trim()
        .strip_prefix("listening on ")
        .unwrap_or_else(|| panic!("unexpected first line: {line:?}"))
        .split(' ')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    Proxy { child, addr }
}

struct Resp {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Resp {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

fn raw(addr: SocketAddr, bytes: &[u8]) -> Resp {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.write_all(bytes).unwrap();
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf);
    let split = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or_else(|| panic!("no response: {:?}", String::from_utf8_lossy(&buf)));
    let head = String::from_utf8_lossy(&buf[..split]).into_owned();
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .unwrap()
        .split(' ')
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    Resp {
        status,
        headers,
        body: buf[split + 4..].to_vec(),
    }
}

/// Send one request. `token` becomes `Authorization: Bearer <token>`.
fn call(
    p: &Proxy,
    method: &str,
    target: &str,
    token: Option<&str>,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
) -> Resp {
    let mut req = format!("{method} {target} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n");
    if let Some(t) = token {
        req.push_str(&format!("Authorization: Bearer {t}\r\n"));
    }
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    if let Some(b) = body {
        req.push_str(&format!("Content-Length: {}\r\n", b.len()));
    }
    req.push_str("\r\n");
    let mut bytes = req.into_bytes();
    if let Some(b) = body {
        bytes.extend_from_slice(b);
    }
    raw(p.addr, &bytes)
}

fn get(p: &Proxy, target: &str, token: &str) -> Resp {
    call(p, "GET", target, Some(token), &[], None)
}

fn post_json(p: &Proxy, target: &str, token: &str, json: &str) -> Resp {
    call(
        p,
        "POST",
        target,
        Some(token),
        &[("Content-Type", "application/json")],
        Some(json.as_bytes()),
    )
}

/// A running proxy over a fresh store with a fake upstream.
struct Rig {
    env: Env,
    up: Upstream,
    proxy: Proxy,
}

fn rig() -> Rig {
    rig_with("")
}

fn rig_with(globals: &str) -> Rig {
    let env = Env::new();
    let up = Upstream::start();
    env.write_config(up.addr, globals);
    let proxy = start_proxy(&env, &[]);
    Rig { env, up, proxy }
}

/// A refusal reaches the client as a generic body and never reaches the upstream.
fn assert_refused(r: &Resp, status: u16) {
    assert_eq!(r.status, status, "body: {}", r.text());
    let body = r.text();
    for leak in [
        SECRET,
        OTHER_SECRET,
        "caveat",
        "signature",
        "macaroon",
        "expired",
    ] {
        assert!(!body.contains(leak), "refusal body leaks {leak:?}: {body}");
    }
}

// ---- tests ------------------------------------------------------------------------

#[test]
fn allowed_request_injects_credential_and_hides_the_agent_token() {
    let r = rig();
    let token = r.env.mint(&["--secret", "github_token"]);

    let resp = call(
        &r.proxy,
        "POST",
        "/api/v1/items?x=1&y=two",
        Some(&token),
        &[
            ("Content-Type", "application/json"),
            ("Cookie", "sid=abc"),
            ("Proxy-Authorization", "Basic eHh4"),
            ("X-Llms-Token", "ignored-because-authorization-wins"),
            ("X-HTTP-Method-Override", "DELETE"),
            ("X-Forwarded-For", "203.0.113.9"),
            ("X-Forwarded-Host", "evil.example"),
            ("X-Original-URL", "/admin"),
            ("X-Custom", "keep-me"),
        ],
        Some(br#"{"name":"BODYMARKER"}"#),
    );
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(resp.text(), r#"{"ok":true}"#);
    assert_eq!(
        resp.header("x-upstream"),
        Some("yes"),
        "upstream headers pass through"
    );

    assert_eq!(r.up.hits(), 1);
    let seen = r.up.last();
    assert_eq!(seen.method, "POST");
    assert_eq!(
        seen.url, "/v1/items?x=1&y=two",
        "service segment is stripped, query kept"
    );
    assert_eq!(seen.body, br#"{"name":"BODYMARKER"}"#);
    // Exactly one Authorization header, and it carries the real credential.
    assert_eq!(
        seen.header("authorization"),
        vec![format!("Bearer {SECRET}")]
    );
    for gone in [
        "x-llms-token",
        "cookie",
        "proxy-authorization",
        "x-http-method-override",
        "x-forwarded-for",
        "x-forwarded-host",
        "x-original-url",
    ] {
        assert!(seen.header(gone).is_empty(), "{gone} must not be forwarded");
    }
    assert_eq!(seen.header("x-custom"), vec!["keep-me"]);
    assert_eq!(
        seen.header("host"),
        vec![r.up.addr.to_string()],
        "the upstream host comes from config, never from the request"
    );
    assert!(
        seen.headers.iter().all(|(_, v)| !v.contains(&token)),
        "the agent's macaroon must never reach the upstream"
    );
}

#[test]
fn injection_modes_basic_and_named_header() {
    let r = rig();

    let basic = r.env.mint(&["--secret", "basic_cred"]);
    assert_eq!(get(&r.proxy, "/basic/x", &basic).status, 200);
    assert_eq!(
        r.up.last().header("authorization"),
        vec![format!("Basic {}", B64.encode(BASIC_SECRET))]
    );

    let hdr = r.env.mint(&["--secret", "hdr_cred"]);
    let resp = call(
        &r.proxy,
        "GET",
        "/hdr/x",
        Some(&hdr),
        &[("X-Api-Key", "agent-supplied-evil")],
        None,
    );
    assert_eq!(resp.status, 200);
    let seen = r.up.last();
    assert_eq!(
        seen.header("x-api-key"),
        vec![HDR_SECRET],
        "agent value replaced, not duplicated"
    );
    assert!(
        seen.header("authorization").is_empty(),
        "the agent's bearer token is stripped"
    );
}

#[test]
fn x_llms_token_header_is_accepted() {
    let r = rig();
    let token = r.env.mint(&["--secret", "github_token"]);
    let resp = call(
        &r.proxy,
        "GET",
        "/api/x",
        None,
        &[("X-Llms-Token", &token)],
        None,
    );
    assert_eq!(resp.status, 200);
    assert_eq!(
        r.up.last().header("authorization"),
        vec![format!("Bearer {SECRET}")]
    );
}

#[test]
fn each_request_caveat_denies_and_never_reaches_the_upstream() {
    let r = rig();
    let expected_hits = std::cell::Cell::new(0usize);
    let allowed = |resp: Resp| {
        assert_eq!(resp.status, 200, "{}", resp.text());
        expected_hits.set(expected_hits.get() + 1);
        assert_eq!(r.up.hits(), expected_hits.get());
    };
    let denied = |resp: Resp| {
        assert_refused(&resp, 403);
        assert_eq!(
            r.up.hits(),
            expected_hits.get(),
            "a denied request must not reach the upstream"
        );
    };
    // Each token gets a positive control so a denial is attributable to the caveat, not setup.

    // method_in
    let t = r.env.mint(&["--secret", "github_token", "--method", "GET"]);
    allowed(get(&r.proxy, "/api/x", &t));
    denied(call(&r.proxy, "POST", "/api/x", Some(&t), &[], Some(b"{}")));
    denied(call(&r.proxy, "DELETE", "/api/x", Some(&t), &[], None));

    // path_glob
    let t = r
        .env
        .mint(&["--secret", "github_token", "--path", "/v1/items/*"]);
    allowed(get(&r.proxy, "/api/v1/items/7", &t));
    denied(get(&r.proxy, "/api/v1/other", &t));
    denied(get(&r.proxy, "/api/v1/items/7/extra", &t));

    // host_in (the host is fixed by config, so this is defence in depth)
    let t = r
        .env
        .mint(&["--secret", "github_token", "--host", "127.0.0.1"]);
    allowed(get(&r.proxy, "/api/x", &t));
    let t = r
        .env
        .mint(&["--secret", "github_token", "--host", "api.example.com"]);
    denied(get(&r.proxy, "/api/x", &t));

    // body_eq
    let t = r
        .env
        .mint(&["--secret", "github_token", "--body-eq", "/private=true"]);
    allowed(post_json(&r.proxy, "/api/repos", &t, r#"{"private":true}"#));
    denied(post_json(
        &r.proxy,
        "/api/repos",
        &t,
        r#"{"private":false}"#,
    ));
    denied(post_json(&r.proxy, "/api/repos", &t, r#"{"name":"x"}"#));
    // Not declared as JSON: the body is not inspected, so a body caveat fails closed.
    denied(call(
        &r.proxy,
        "POST",
        "/api/repos",
        Some(&t),
        &[("Content-Type", "text/plain")],
        Some(br#"{"private":true}"#),
    ));
    // No body at all.
    denied(call(&r.proxy, "POST", "/api/repos", Some(&t), &[], None));

    // body_keys_in
    let t = r.env.mint(&[
        "--secret",
        "github_token",
        "--body-key",
        "name",
        "--body-key",
        "private",
    ]);
    allowed(post_json(
        &r.proxy,
        "/api/repos",
        &t,
        r#"{"name":"a","private":true}"#,
    ));
    denied(post_json(
        &r.proxy,
        "/api/repos",
        &t,
        r#"{"name":"a","admin":true}"#,
    ));
    denied(post_json(&r.proxy, "/api/repos", &t, r#"["name"]"#));

    // body_glob
    let t = r
        .env
        .mint(&["--secret", "github_token", "--body-glob", "/name=proj-*"]);
    allowed(post_json(
        &r.proxy,
        "/api/repos",
        &t,
        r#"{"name":"proj-x"}"#,
    ));
    denied(post_json(&r.proxy, "/api/repos", &t, r#"{"name":"other"}"#));
}

#[test]
fn duplicate_keys_and_bad_json_are_refused() {
    let r = rig();
    let t = r
        .env
        .mint(&["--secret", "github_token", "--body-eq", "/private=true"]);
    // A parser that keeps the first value would see `true`; one that keeps the last, `false`.
    let resp = post_json(
        &r.proxy,
        "/api/repos",
        &t,
        r#"{"private":true,"private":false}"#,
    );
    assert_refused(&resp, 400);
    let resp = post_json(&r.proxy, "/api/repos", &t, r#"{"private":true"#);
    assert_refused(&resp, 400);
    assert_eq!(r.up.hits(), 0);
}

#[test]
fn missing_garbled_expired_and_tampered_tokens_get_403_with_no_upstream_call() {
    let r = rig();
    let good = r.env.mint(&["--secret", "github_token"]);

    // No token, wrong scheme, garbage, truncated.
    assert_refused(&call(&r.proxy, "GET", "/api/x", None, &[], None), 403);
    assert_refused(
        &call(
            &r.proxy,
            "GET",
            "/api/x",
            None,
            &[("Authorization", "Basic Zm9vOmJhcg==")],
            None,
        ),
        403,
    );
    assert_refused(&get(&r.proxy, "/api/x", "garbage"), 403);
    assert_refused(&get(&r.proxy, "/api/x", &good[..good.len() / 2]), 403);

    // Tampered: drop a caveat, or alter the signature.
    let mut v: serde_json::Value = serde_json::from_slice(&B64URL.decode(&good).unwrap()).unwrap();
    let mut dropped = v.clone();
    dropped["caveats"].as_array_mut().unwrap().pop();
    let forged = B64URL.encode(serde_json::to_vec(&dropped).unwrap());
    assert_refused(&get(&r.proxy, "/api/x", &forged), 403);

    let sig = v["signature"].as_str().unwrap().to_string();
    let flipped = format!(
        "{}{}",
        if sig.starts_with('A') { 'B' } else { 'A' },
        &sig[1..]
    );
    v["signature"] = flipped.into();
    let forged = B64URL.encode(serde_json::to_vec(&v).unwrap());
    assert_refused(&get(&r.proxy, "/api/x", &forged), 403);

    // Expired.
    let short = r.env.mint_ttl("1s", &["--secret", "github_token"]);
    std::thread::sleep(Duration::from_millis(2200));
    assert_refused(&get(&r.proxy, "/api/x", &short), 403);

    assert_eq!(r.up.hits(), 0, "none of these may reach the upstream");
    // Control: the untouched token works.
    assert_eq!(get(&r.proxy, "/api/x", &good).status, 200);
}

#[test]
fn token_for_another_secret_or_a_bare_session_token_is_refused() {
    let r = rig();

    let other = r.env.mint(&["--secret", "other_token"]);
    assert_refused(&get(&r.proxy, "/api/x", &other), 403);

    // The root session macaroon has no secret caveat: it must not be accepted as a blanket key.
    let session = std::fs::read(r.env.store().join("session.json")).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&session).unwrap();
    let root = B64URL.encode(serde_json::to_vec(&v).unwrap());
    assert_refused(&get(&r.proxy, "/api/x", &root), 403);
    assert_eq!(r.up.hits(), 0);

    // A token naming several secrets, including this one, is fine.
    let multi = r
        .env
        .mint(&["--secret", "github_token", "--secret", "other_token"]);
    assert_eq!(get(&r.proxy, "/api/x", &multi).status, 200);
}

#[test]
fn path_traversal_and_target_tricks_are_400() {
    let r = rig();
    let t = r.env.mint(&["--secret", "github_token"]);
    let abs = format!(
        "GET http://evil.example/x HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {t}\r\nConnection: close\r\n\r\n"
    );
    assert_refused(&raw(r.proxy.addr, abs.as_bytes()), 400);

    for target in [
        "/api/a/../b",
        "/api/a/./b",
        "/api/a/%2e%2e/b",
        "/api/a/%2E%2E/b",
        "/api/a%2Fb",
        "/api/a%2fb",
        "/api/a%5Cb",
        "/api/a%00b",
        "/api//b",
        "//evil.example/x",
        "/api/x#frag",
        "/api/a%zz",
        "/api/a\\b",
    ] {
        let resp = get(&r.proxy, target, &t);
        assert_refused(&resp, 400);
    }
    assert_eq!(r.up.hits(), 0, "nothing ambiguous may reach the upstream");
    // Control.
    assert_eq!(get(&r.proxy, "/api/a/b", &t).status, 200);
}

#[test]
fn unknown_service_and_odd_methods_are_refused() {
    let r = rig();
    let t = r.env.mint(&["--secret", "github_token"]);
    assert_refused(&get(&r.proxy, "/nope/x", &t), 404);
    assert_refused(&get(&r.proxy, "/", &t), 400);
    assert_refused(&call(&r.proxy, "TRACE", "/api/x", Some(&t), &[], None), 405);
    assert_eq!(r.up.hits(), 0);
}

#[test]
fn redirects_are_not_followed() {
    let r = rig();
    let t = r.env.mint(&["--secret", "github_token"]);
    let resp = get(&r.proxy, "/api/redirect", &t);
    assert_eq!(resp.status, 302);
    let loc = resp
        .header("location")
        .expect("Location passes through untouched");
    assert!(
        loc.ends_with("/stolen") && loc.starts_with("http://127.0.0.1:"),
        "{loc}"
    );
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        r.up.other_hits.load(Ordering::SeqCst),
        0,
        "the redirect target was contacted"
    );
    assert_eq!(r.up.hits(), 1);
}

#[test]
fn oversized_bodies_are_rejected() {
    let r = rig_with("max_body_bytes = 1024\n");
    let t = r.env.mint(&["--secret", "github_token"]);
    let fits = vec![b'a'; 1024];
    let too_big = vec![b'a'; 1025];
    let huge = vec![b'a'; 64 * 1024];

    let ok = call(
        &r.proxy,
        "POST",
        "/api/x",
        Some(&t),
        &[("Content-Type", "text/plain")],
        Some(&fits),
    );
    assert_eq!(ok.status, 200);
    assert_eq!(r.up.hits(), 1);
    for body in [&too_big, &huge] {
        let resp = call(
            &r.proxy,
            "POST",
            "/api/x",
            Some(&t),
            &[("Content-Type", "text/plain")],
            Some(body),
        );
        assert_refused(&resp, 413);
    }
    assert_eq!(r.up.hits(), 1, "an oversized body must not be forwarded");
}

#[test]
fn a_slow_upstream_times_out_with_a_generic_502() {
    let r = rig_with("timeout_secs = 1\n");
    let t = r.env.mint(&["--secret", "github_token"]);
    let started = std::time::Instant::now();
    let resp = get(&r.proxy, "/api/slow", &t);
    assert_refused(&resp, 502);
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "the proxy must give up at the configured timeout, not wait for the upstream"
    );
}

#[test]
fn headers_echoing_the_credential_are_stripped_from_responses() {
    let r = rig();
    let t = r.env.mint(&["--secret", "github_token"]);
    let resp = get(&r.proxy, "/api/echo", &t);
    assert_eq!(resp.status, 200);
    assert!(
        resp.header("x-echo-auth").is_none(),
        "echoed credential must be dropped"
    );
    assert_eq!(
        resp.header("x-upstream"),
        Some("yes"),
        "other headers survive"
    );
    assert!(!format!("{:?}", resp.headers).contains(SECRET));
}

#[test]
fn audit_records_decisions_but_never_secrets_tokens_or_bodies() {
    let r = rig();
    let t = r
        .env
        .mint(&["--secret", "github_token", "--method", "POST"]);
    assert_eq!(
        post_json(
            &r.proxy,
            "/api/v1/items?q=QUERYMARKER",
            &t,
            r#"{"name":"BODYMARKER"}"#
        )
        .status,
        200
    );
    assert_refused(&get(&r.proxy, "/api/v1/items", &t), 403); // method_in
    assert_refused(&get(&r.proxy, "/api/a/../b", &t), 400);
    assert_refused(&get(&r.proxy, "/api/x", "garbage"), 403);

    let log = r.env.audit_json();
    let entries: Vec<serde_json::Value> = log
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .filter(|e: &serde_json::Value| e["event"] == "proxy.request")
        .collect();
    let notes: Vec<String> = entries
        .iter()
        .map(|e| e["note"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(notes.len(), 4, "{notes:#?}");

    assert!(
        notes
            .iter()
            .any(|n| n == "service=api method=POST host=127.0.0.1 path=/v1/items decision=allow"),
        "{notes:#?}"
    );
    assert!(
        notes.iter().any(|n| n.contains("method=GET")
            && n.contains("decision=deny")
            && n.contains("reason=caveat:method_in")),
        "{notes:#?}"
    );
    assert!(
        notes
            .iter()
            .any(|n| n.contains("decision=deny") && n.contains("reason=bad_path")),
        "{notes:#?}"
    );
    assert!(
        notes.iter().any(|n| n.contains("reason=token_invalid")),
        "{notes:#?}"
    );
    // The audited key is the secret's *name*.
    assert!(entries.iter().any(|e| e["key"] == "github_token"));

    for leak in [SECRET, &t, "BODYMARKER", "QUERYMARKER", "Bearer"] {
        assert!(!log.contains(leak), "audit log leaks {leak:?}");
    }
}

#[test]
fn revocation_and_rotation_take_effect_immediately() {
    let r = rig();
    let t = r.env.mint(&["--secret", "github_token"]);
    assert_eq!(get(&r.proxy, "/api/x", &t).status, 200);

    // revoke-all deletes the root key the proxy verifies against.
    r.env.llms().arg("revoke-all").assert().success();
    assert_refused(&get(&r.proxy, "/api/x", &t), 403);
    let hits = r.up.hits();

    // A fresh session gives a new root key; the old token stays dead, a new one works.
    r.env.session();
    assert_refused(&get(&r.proxy, "/api/x", &t), 403);
    let t2 = r.env.mint(&["--secret", "github_token"]);
    assert_eq!(get(&r.proxy, "/api/x", &t2).status, 200);
    assert_eq!(r.up.hits(), hits + 1);

    // --rotate re-encrypts the store under a new age key. The proxy decrypts per request, so it
    // keeps injecting the right value without a restart.
    r.env
        .llms()
        .args(["revoke-all", "--rotate"])
        .assert()
        .success();
    r.env.session();
    let t3 = r.env.mint(&["--secret", "github_token"]);
    assert_eq!(get(&r.proxy, "/api/x", &t3).status, 200);
    assert_eq!(
        r.up.last().header("authorization"),
        vec![format!("Bearer {SECRET}")]
    );
}

#[test]
fn non_loopback_bind_is_refused_without_the_flag() {
    let env = Env::new();
    let up = Upstream::start();
    env.write_config(up.addr, "");
    let out = env
        .llms()
        .args([
            "proxy",
            "serve",
            "--bind",
            "0.0.0.0:0",
            "--allow-loopback-http",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("non-loopback") && err.contains("--allow-non-loopback"),
        "{err}"
    );

    // Explicit opt-in works, with a warning.
    let mut child = env
        .spawn_proxy(&[
            "--bind",
            "0.0.0.0:0",
            "--allow-non-loopback",
            "--allow-loopback-http",
        ])
        .unwrap();
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let _ = child.kill();
    let _ = child.wait();
    assert!(line.starts_with("listening on "), "{line:?}");

    // Anything that is not an IP:PORT is refused too.
    let out = env
        .llms()
        .args(["proxy", "serve", "--bind", "localhost:8787"])
        .output()
        .unwrap();
    assert!(!out.status.success());
}

#[test]
fn http_upstream_needs_the_loopback_flag() {
    let env = Env::new();
    let up = Upstream::start();
    env.write_config(up.addr, "");
    // Without --allow-loopback-http the config is rejected: upstreams must be https.
    let out = env
        .llms()
        .args(["proxy", "serve", "--bind", "127.0.0.1:0"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("https"));
}

#[test]
fn check_validates_config_and_secrets_without_serving() {
    let env = Env::new();
    let up = Upstream::start();
    env.write_config(up.addr, "");

    let ok = env
        .llms()
        .args([
            "proxy",
            "check",
            "--service",
            "api",
            "--allow-loopback-http",
        ])
        .output()
        .unwrap();
    let out = String::from_utf8_lossy(&ok.stdout);
    assert!(
        ok.status.success(),
        "{out}{}",
        String::from_utf8_lossy(&ok.stderr)
    );
    assert!(
        out.contains("api:") && out.contains("github_token") && out.contains("[ok]"),
        "{out}"
    );
    assert!(!out.contains(SECRET), "check must never print a secret");

    // Unknown service.
    let bad = env
        .llms()
        .args([
            "proxy",
            "check",
            "--service",
            "nope",
            "--allow-loopback-http",
        ])
        .output()
        .unwrap();
    assert!(!bad.status.success());

    // A secret that is not in the store.
    std::fs::write(
        env.config_path(),
        format!(
            "[services.ghost]\nupstream = \"http://{}\"\nsecret = \"no_such_secret\"\ninject = \"bearer\"\n",
            up.addr
        ),
    )
    .unwrap();
    let missing = env
        .llms()
        .args(["proxy", "check", "--allow-loopback-http"])
        .output()
        .unwrap();
    assert!(!missing.status.success());
    assert!(String::from_utf8_lossy(&missing.stdout).contains("MISSING"));

    // Plain http without the flag.
    let strict = env.llms().args(["proxy", "check"]).output().unwrap();
    assert!(!strict.status.success());
    assert!(String::from_utf8_lossy(&strict.stderr).contains("https"));
}

#[test]
fn mint_flags_validate_their_input() {
    let env = Env::new();
    for args in [
        vec!["--body-eq", "private=true"], // pointer must start with '/'
        vec!["--body-eq", "/private"],     // no value
        vec!["--body-eq", "/private=tru"], // not JSON
        vec!["--path", "v1/items"],        // must start with '/'
    ] {
        let out = env
            .llms()
            .args(["macaroon", "mint", "--secret", "github_token"])
            .args(&args)
            .output()
            .unwrap();
        assert!(!out.status.success(), "{args:?} should be refused");
    }
    // The caveats show up in `inspect` in readable form.
    let t = env.mint(&[
        "--secret",
        "github_token",
        "--method",
        "get",
        "--path",
        "/v1/*",
    ]);
    let out = env
        .llms()
        .args(["macaroon", "inspect", "--macaroon", &t])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("GET") && text.contains("/v1/*"), "{text}");
}

#[test]
fn request_scoped_tokens_do_not_release_secrets_outside_the_proxy() {
    // Fail closed: `exec` has no request context, so a request-scoped token cannot be used there.
    let env = Env::new();
    let t = env.mint(&["--secret", "github_token", "--method", "GET"]);
    let out = env
        .llms()
        .args([
            "exec",
            "--inject",
            "X=github_token",
            "--macaroon",
            &t,
            "--",
            "true",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
}

impl Env {
    fn mint_ttl(&self, ttl: &str, args: &[&str]) -> String {
        let out = self
            .llms()
            .args(["macaroon", "mint", "--ttl", ttl])
            .args(args)
            .output()
            .unwrap();
        assert!(out.status.success());
        String::from_utf8(out.stdout).unwrap().trim().to_string()
    }
}
