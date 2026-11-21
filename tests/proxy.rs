//! End-to-end tests for `llms proxy`. Each test runs the real binary against a fake upstream
//! (a `tiny_http` thread on 127.0.0.1) with its own store, so there is no real network and no
//! shared environment. The hidden `--allow-insecure-upstream` flag is what lets the proxy talk
//! plain HTTP to that fake; production configs are https-only.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Child, Stdio};
use std::sync::{Arc, Mutex};

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

const SECRET: &str = "s3cr3t-upstream-credential";

fn llms_in(env: &Env) -> Command {
    let mut c = Command::cargo_bin("llms").unwrap();
    c.env("LLM_SECRETS_DIR", env.store.path())
        .env("LLM_SECRETS_CONFIG_DIR", env.cfg.path())
        .current_dir(env.work.path());
    c
}

struct Env {
    store: TempDir,
    cfg: TempDir,
    work: TempDir,
}

impl Env {
    fn new() -> Self {
        let env = Env {
            store: tempfile::tempdir().unwrap(),
            cfg: tempfile::tempdir().unwrap(),
            work: tempfile::tempdir().unwrap(),
        };
        llms_in(&env).arg("init").assert().success();
        llms_in(&env)
            .args(["session-start", "--ttl", "1h"])
            .assert()
            .success();
        for (name, value) in [("gh", SECRET), ("other", "other-secret")] {
            llms_in(&env)
                .args(["set", name, "--stdin"])
                .write_stdin(value)
                .assert()
                .success();
        }
        env
    }

    fn mint(&self, extra: &[&str]) -> String {
        let mut args = vec!["macaroon", "mint", "--secret", "gh", "--ttl", "1h"];
        args.extend_from_slice(extra);
        let out = llms_in(self).args(args).output().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap().trim().to_string()
    }

    fn audit(&self) -> String {
        std::fs::read_to_string(self.store.path().join("audit.jsonl")).unwrap_or_default()
    }
}

// ---- fake upstream --------------------------------------------------------

#[derive(Debug, Clone)]
struct Seen {
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    body: String,
}

struct Upstream {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl Upstream {
    fn start() -> Self {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let addr = server.server_addr().to_ip().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&seen);
        std::thread::spawn(move || {
            for mut req in server.incoming_requests() {
                let mut body = String::new();
                let _ = req.as_reader().read_to_string(&mut body);
                let headers: Vec<(String, String)> = req
                    .headers()
                    .iter()
                    .map(|h| (h.field.to_string().to_lowercase(), h.value.to_string()))
                    .collect();
                let url = req.url().to_string();
                let auth = headers
                    .iter()
                    .find(|(n, _)| n == "authorization")
                    .map(|(_, v)| v.clone())
                    .unwrap_or_default();
                log.lock().unwrap().push(Seen {
                    method: req.method().to_string(),
                    url: url.clone(),
                    headers,
                    body,
                });
                let mut resp = tiny_http::Response::from_string("{\"ok\":true}");
                if url.starts_with("/redirect") {
                    resp = tiny_http::Response::from_string("moved")
                        .with_status_code(302)
                        .with_header(
                            tiny_http::Header::from_bytes(
                                &b"Location"[..],
                                &b"http://127.0.0.1:9/stolen"[..],
                            )
                            .unwrap(),
                        );
                } else if url.starts_with("/echo") {
                    resp = resp.with_header(
                        tiny_http::Header::from_bytes(&b"X-Echo"[..], auth.as_bytes()).unwrap(),
                    );
                }
                let _ = req.respond(resp.with_header(
                    tiny_http::Header::from_bytes(&b"X-Fine"[..], &b"yes"[..]).unwrap(),
                ));
            }
        });
        Upstream { addr, seen }
    }

    fn calls(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
}

// ---- proxy under test -----------------------------------------------------

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

fn write_config(env: &Env, up: &Upstream, extra_top: &str) -> std::path::PathBuf {
    let path = env.cfg.path().join("services.toml");
    std::fs::write(
        &path,
        format!(
            "{extra_top}\n[services.gh]\nupstream = \"http://{}\"\nsecret = \"gh\"\ninject = \"bearer\"\n",
            up.addr
        ),
    )
    .unwrap();
    path
}

fn start_proxy(env: &Env, up: &Upstream, extra_top: &str) -> Proxy {
    let cfg = write_config(env, up, extra_top);
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin("llms"));
    cmd.args([
        "proxy",
        "serve",
        "--bind",
        "127.0.0.1:0",
        "--allow-insecure-upstream",
    ])
    .arg("--config")
    .arg(&cfg)
    .env("LLM_SECRETS_DIR", env.store.path())
    .env("LLM_SECRETS_CONFIG_DIR", env.cfg.path())
    .env_remove("HTTP_PROXY")
    .env_remove("http_proxy")
    .env_remove("HTTPS_PROXY")
    .env_remove("https_proxy")
    .env_remove("ALL_PROXY")
    .env_remove("all_proxy")
    .env("NO_PROXY", "127.0.0.1")
    .current_dir(env.work.path())
    .stdout(Stdio::piped())
    .stderr(Stdio::null());
    let mut child = cmd.spawn().unwrap();
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let addr: SocketAddr = line
        .split("http://")
        .nth(1)
        .and_then(|s| s.split_whitespace().next())
        .unwrap_or_else(|| panic!("no listen line: {line:?}"))
        .parse()
        .unwrap();
    Proxy { child, addr }
}

struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl Reply {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Raw HTTP/1.1 client so tests control the exact bytes of the request target.
fn send(p: &Proxy, method: &str, target: &str, headers: &[(&str, &str)], body: &[u8]) -> Reply {
    let mut s = TcpStream::connect(p.addr).unwrap();
    let mut req = format!(
        "{method} {target} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
        p.addr
    );
    for (n, v) in headers {
        req.push_str(&format!("{n}: {v}\r\n"));
    }
    if !body.is_empty() {
        req.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes()).unwrap();
    s.write_all(body).unwrap();
    let mut raw = Vec::new();
    let _ = s.read_to_end(&mut raw);
    let text = String::from_utf8_lossy(&raw).to_string();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let mut lines = head.lines();
    let status = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(n, v)| (n.trim().to_string(), v.trim().to_string()))
        .collect();
    Reply {
        status,
        headers,
        body: body.to_string(),
    }
}

fn bearer(tok: &str) -> String {
    format!("Bearer {tok}")
}

fn json_post(p: &Proxy, target: &str, tok: &str, body: &str) -> Reply {
    send(
        p,
        "POST",
        target,
        &[
            ("Authorization", &bearer(tok)),
            ("Content-Type", "application/json"),
        ],
        body.as_bytes(),
    )
}

// ---- tests ----------------------------------------------------------------

#[test]
fn allowed_request_injects_credential_and_hides_agent_token() {
    let env = Env::new();
    let up = Upstream::start();
    let proxy = start_proxy(&env, &up, "");
    let tok = env.mint(&[
        "--host",
        "127.0.0.1",
        "--method",
        "POST",
        "--path-glob",
        "/repos/acme/*",
        "--body-eq",
        "/private=true",
        "--body-glob",
        "/name=proj-*",
        "--body-keys",
        "name,private",
    ]);
    let r = send(
        &proxy,
        "POST",
        "/gh/repos/acme/new?marker=QUERYMARK",
        &[
            ("Authorization", &bearer(&tok)),
            ("Content-Type", "application/json"),
            ("Cookie", "session=abc"),
            ("Proxy-Authorization", "Basic eHg6eHg="),
            ("X-Custom", "kept"),
        ],
        br#"{"name":"proj-1","private":true}"#,
    );
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.header("x-fine"), Some("yes"));

    let calls = up.calls();
    assert_eq!(calls.len(), 1);
    let c = &calls[0];
    assert_eq!(c.method, "POST");
    assert_eq!(c.url, "/repos/acme/new?marker=QUERYMARK");
    assert_eq!(c.body, r#"{"name":"proj-1","private":true}"#);
    let auth: Vec<_> = c
        .headers
        .iter()
        .filter(|(n, _)| n == "authorization")
        .collect();
    assert_eq!(auth.len(), 1);
    assert_eq!(auth[0].1, format!("Bearer {SECRET}"));
    for (n, v) in &c.headers {
        assert!(!v.contains(&tok), "agent token leaked in {n}");
        assert!(
            !["cookie", "x-llms-token", "proxy-authorization"].contains(&n.as_str()),
            "{n}"
        );
    }
    assert!(
        c.headers
            .iter()
            .any(|(n, v)| n == "x-custom" && v == "kept")
    );

    // Audit: allow recorded, nothing sensitive in it.
    let audit = env.audit();
    assert!(audit.contains("proxy.allow") && audit.contains("service=gh"));
    for forbidden in [SECRET, tok.as_str(), "QUERYMARK", "proj-1", "session=abc"] {
        assert!(!audit.contains(forbidden), "audit leaked {forbidden}");
    }
}

#[test]
fn x_llms_token_header_is_accepted() {
    let env = Env::new();
    let up = Upstream::start();
    let proxy = start_proxy(&env, &up, "");
    let tok = env.mint(&[]);
    let r = send(&proxy, "GET", "/gh/x", &[("X-Llms-Token", &tok)], b"");
    assert_eq!(r.status, 200);
    let c = &up.calls()[0];
    assert!(c.headers.iter().all(|(n, _)| n != "x-llms-token"));
    assert!(
        c.headers
            .iter()
            .any(|(n, v)| n == "authorization" && v == &format!("Bearer {SECRET}"))
    );
}

#[test]
fn each_caveat_type_is_enforced() {
    let env = Env::new();
    let up = Upstream::start();
    let proxy = start_proxy(&env, &up, "");
    let body = r#"{"name":"proj-1","private":true}"#;

    // (extra mint args, method, path, body)
    let cases: Vec<(Vec<&str>, &str, &str, &str, &str)> = vec![
        (vec!["--method", "GET"], "POST", "/gh/x", body, "method_in"),
        (
            vec!["--path-glob", "/repos/acme/*"],
            "POST",
            "/gh/repos/evil/x",
            body,
            "path_glob",
        ),
        (
            vec!["--body-eq", "/private=true"],
            "POST",
            "/gh/x",
            r#"{"private":false}"#,
            "body_eq",
        ),
        (
            vec!["--body-glob", "/name=proj-*"],
            "POST",
            "/gh/x",
            r#"{"name":"evil"}"#,
            "body_glob",
        ),
        (
            vec!["--body-keys", "name,private"],
            "POST",
            "/gh/x",
            r#"{"name":"a","private":true,"admin":true}"#,
            "body_keys_in",
        ),
        (
            vec!["--host", "api.other.example"],
            "POST",
            "/gh/x",
            body,
            "host_in",
        ),
    ];
    for (mint, method, path, b, name) in cases {
        let tok = env.mint(&mint);
        let r = send(
            &proxy,
            method,
            path,
            &[
                ("Authorization", &bearer(&tok)),
                ("Content-Type", "application/json"),
            ],
            b.as_bytes(),
        );
        assert_eq!(r.status, 403, "{name}");
        assert_eq!(r.body, "forbidden\n", "{name}: body must be generic");
    }
    assert!(
        up.calls().is_empty(),
        "upstream must never be called on a denial"
    );

    let audit = env.audit();
    for name in [
        "method_in",
        "path_glob",
        "body_eq",
        "body_glob",
        "body_keys_in",
        "host_in",
    ] {
        assert!(
            audit.contains(&format!("failed={name}")),
            "audit missing {name}:\n{audit}"
        );
    }
    assert!(
        !audit.contains("admin") && !audit.contains("evil\\\""),
        "no body content in audit"
    );
}

#[test]
fn body_caveats_fail_closed_without_json() {
    let env = Env::new();
    let up = Upstream::start();
    let proxy = start_proxy(&env, &up, "");
    let tok = env.mint(&["--body-keys", "name"]);
    // Non-JSON content type: body caveats see None.
    let r = send(
        &proxy,
        "POST",
        "/gh/x",
        &[
            ("Authorization", &bearer(&tok)),
            ("Content-Type", "text/plain"),
        ],
        br#"{"name":"a"}"#,
    );
    assert_eq!(r.status, 403);
    // No body at all.
    let r = send(
        &proxy,
        "POST",
        "/gh/x",
        &[("Authorization", &bearer(&tok))],
        b"",
    );
    assert_eq!(r.status, 403);
    // Malformed JSON with a JSON content type, and duplicate keys: 400.
    assert_eq!(json_post(&proxy, "/gh/x", &tok, "{not json").status, 400);
    assert_eq!(
        json_post(&proxy, "/gh/x", &tok, r#"{"name":"a","name":"b"}"#).status,
        400
    );
    assert!(up.calls().is_empty());
}

#[test]
fn bad_tokens_are_rejected_without_upstream_call() {
    let env = Env::new();
    let up = Upstream::start();
    let proxy = start_proxy(&env, &up, "");
    let good = env.mint(&[]);

    // Tampered: well-formed token whose caveat list no longer matches its signature.
    let tampered = {
        use base64::Engine as _;
        let e = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let mut m: serde_json::Value = serde_json::from_slice(&e.decode(&good).unwrap()).unwrap();
        m["caveats"][0] = serde_json::json!({"type": "secret_eq", "value": "other"});
        e.encode(serde_json::to_vec(&m).unwrap())
    };

    let expired = {
        let out = llms_in(&env)
            .args(["macaroon", "mint", "--secret", "gh", "--ttl", "1s"])
            .output()
            .unwrap();
        String::from_utf8(out.stdout).unwrap().trim().to_string()
    };
    std::thread::sleep(std::time::Duration::from_millis(2100));

    // A valid token for a different secret.
    let other = {
        let out = llms_in(&env)
            .args(["macaroon", "mint", "--secret", "other", "--ttl", "1h"])
            .output()
            .unwrap();
        String::from_utf8(out.stdout).unwrap().trim().to_string()
    };
    // The root session token carries no secret caveat at all.
    let root = std::fs::read_to_string(env.store.path().join("session.json")).unwrap();
    let root = {
        let m: serde_json::Value = serde_json::from_str(&root).unwrap();
        use base64::Engine as _;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(&m).unwrap())
    };

    for (label, tok) in [
        ("garbled", "not-a-macaroon".to_string()),
        ("tampered", tampered),
        ("expired", expired),
        ("other-secret", other),
        ("no-secret-caveat", root),
    ] {
        let r = send(
            &proxy,
            "GET",
            "/gh/x",
            &[("Authorization", &bearer(&tok))],
            b"",
        );
        assert_eq!(r.status, 403, "{label}");
        assert_eq!(r.body, "forbidden\n");
    }
    // No token at all.
    assert_eq!(send(&proxy, "GET", "/gh/x", &[], b"").status, 403);
    assert!(up.calls().is_empty());
    let audit = env.audit();
    assert!(audit.contains("failed=expires_at") && audit.contains("failed=secret_eq"));
    assert!(audit.contains("failed=signature_invalid") && audit.contains("failed=no_token"));
}

#[test]
fn ambiguous_paths_and_targets_get_400() {
    let env = Env::new();
    let up = Upstream::start();
    let proxy = start_proxy(&env, &up, "");
    let tok = env.mint(&[]);
    for target in [
        "/gh/a/../b",
        "/gh/./b",
        "/gh/a%2fb",
        "/gh/a%2Fb",
        "/gh/a%2e%2e/b",
        "/gh/a%5cb",
        "/gh/a\\b",
        "/gh//b",
        "/gh/a%00b",
        "http://evil.example/gh/b",
        "/gh/x#frag",
    ] {
        let r = send(
            &proxy,
            "GET",
            target,
            &[("Authorization", &bearer(&tok))],
            b"",
        );
        assert_eq!(r.status, 400, "{target}");
    }
    // A Host override cannot redirect the upstream: it is ignored entirely.
    let r = send(
        &proxy,
        "GET",
        "/gh/ok",
        &[
            ("Authorization", &bearer(&tok)),
            ("X-Forwarded-Host", "evil.example"),
        ],
        b"",
    );
    assert_eq!(r.status, 200);
    assert_eq!(
        up.calls().len(),
        1,
        "only the legitimate request reached upstream"
    );
    assert_eq!(
        send(
            &proxy,
            "GET",
            "/nope/x",
            &[("Authorization", &bearer(&tok))],
            b""
        )
        .status,
        404
    );
}

#[test]
fn redirects_are_not_followed() {
    let env = Env::new();
    let up = Upstream::start();
    let proxy = start_proxy(&env, &up, "");
    let tok = env.mint(&[]);
    let r = send(
        &proxy,
        "GET",
        "/gh/redirect",
        &[("Authorization", &bearer(&tok))],
        b"",
    );
    assert_eq!(r.status, 302);
    assert_eq!(r.header("location"), Some("http://127.0.0.1:9/stolen"));
    assert_eq!(up.calls().len(), 1);
}

#[test]
fn oversized_body_is_rejected() {
    let env = Env::new();
    let up = Upstream::start();
    let proxy = start_proxy(&env, &up, "max_body_bytes = 64");
    let tok = env.mint(&[]);
    let big = format!("{{\"a\":\"{}\"}}", "x".repeat(200));
    let r = json_post(&proxy, "/gh/x", &tok, &big);
    assert_eq!(r.status, 413);
    assert!(up.calls().is_empty());
    // At the limit is fine.
    assert_eq!(json_post(&proxy, "/gh/x", &tok, r#"{"a":1}"#).status, 200);
}

#[test]
fn response_headers_echoing_the_credential_are_dropped() {
    let env = Env::new();
    let up = Upstream::start();
    let proxy = start_proxy(&env, &up, "");
    let tok = env.mint(&[]);
    let r = send(
        &proxy,
        "GET",
        "/gh/echo",
        &[("Authorization", &bearer(&tok))],
        b"",
    );
    assert_eq!(r.status, 200);
    assert!(
        r.header("x-echo").is_none(),
        "echoed credential header must be stripped"
    );
    assert_eq!(r.header("x-fine"), Some("yes"));
}

#[test]
fn revoke_all_and_root_key_rotation_invalidate_tokens() {
    let env = Env::new();
    let up = Upstream::start();
    let proxy = start_proxy(&env, &up, "");

    let tok = env.mint(&[]);
    assert_eq!(
        send(
            &proxy,
            "GET",
            "/gh/x",
            &[("Authorization", &bearer(&tok))],
            b""
        )
        .status,
        200
    );
    // New session rotates the root key.
    llms_in(&env)
        .args(["session-start", "--ttl", "1h"])
        .assert()
        .success();
    assert_eq!(
        send(
            &proxy,
            "GET",
            "/gh/x",
            &[("Authorization", &bearer(&tok))],
            b""
        )
        .status,
        403
    );

    let tok2 = env.mint(&[]);
    assert_eq!(
        send(
            &proxy,
            "GET",
            "/gh/x",
            &[("Authorization", &bearer(&tok2))],
            b""
        )
        .status,
        200
    );
    llms_in(&env).arg("revoke-all").assert().success();
    assert_eq!(
        send(
            &proxy,
            "GET",
            "/gh/x",
            &[("Authorization", &bearer(&tok2))],
            b""
        )
        .status,
        403
    );
    assert_eq!(up.calls().len(), 2);
}

#[test]
fn non_loopback_bind_needs_the_flag() {
    let env = Env::new();
    let up = Upstream::start();
    let cfg = write_config(&env, &up, "");
    llms_in(&env)
        .args([
            "proxy",
            "serve",
            "--bind",
            "0.0.0.0:0",
            "--allow-insecure-upstream",
            "--config",
        ])
        .arg(&cfg)
        .assert()
        .failure()
        .stderr(predicate::str::contains("non-loopback"));
    llms_in(&env)
        .args(["proxy", "serve", "--bind", "not-an-address"])
        .assert()
        .failure();
}

#[test]
fn check_validates_config_and_secret() {
    let env = Env::new();
    let up = Upstream::start();
    let cfg = write_config(&env, &up, "");
    llms_in(&env)
        .args([
            "proxy",
            "check",
            "--service",
            "gh",
            "--allow-insecure-upstream",
            "--config",
        ])
        .arg(&cfg)
        .assert()
        .success()
        .stdout(predicate::str::contains("ok: gh").and(predicate::str::contains(SECRET).not()));
    llms_in(&env)
        .args([
            "proxy",
            "check",
            "--service",
            "missing",
            "--allow-insecure-upstream",
            "--config",
        ])
        .arg(&cfg)
        .assert()
        .failure();
    // http upstream is refused without the testing flag.
    llms_in(&env)
        .args(["proxy", "check", "--service", "gh", "--config"])
        .arg(&cfg)
        .assert()
        .failure()
        .stderr(predicate::str::contains("https"));
}
