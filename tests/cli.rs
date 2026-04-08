//! Integration tests for the `llms` CLI.
//!
//! These are intentionally light — they assert structural invariants of the
//! command surface, not the (yet-to-be-implemented) behaviour of each command.

use assert_cmd::Command;
use predicates::prelude::*;

/// `llms get` must not exist. See `docs/adr/0002-no-get-command.md`.
///
/// This is the architectural guarantee that secrets never leave the binary
/// via stdout. If someone ever adds a `Get` variant to the `Command` enum,
/// this test fails loudly.
#[test]
fn no_get_command_exists() {
    Command::cargo_bin("llms")
        .unwrap()
        .arg("get")
        .arg("anything")
        .assert()
        .failure();
}

/// Belt-and-braces: even the help text must not mention a `get` subcommand.
#[test]
fn help_does_not_advertise_get() {
    Command::cargo_bin("llms")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("\n  get ").not())
        .stdout(predicate::str::contains("\n  get\n").not());
}

/// `--version` should print the crate version.
#[test]
fn version_flag_works() {
    Command::cargo_bin("llms")
        .unwrap()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains(env!("CARGO_PKG_VERSION")));
}

// ---- end-to-end round trip ------------------------------------------------
//
// Each test gets its own LLM_SECRETS_DIR via tempfile so they can run in
// parallel without stepping on one another.

use tempfile::TempDir;

fn llms() -> Command {
    Command::cargo_bin("llms").unwrap()
}

fn fresh_store() -> TempDir {
    let dir = tempfile::tempdir().unwrap();
    llms()
        .env("LLM_SECRETS_DIR", dir.path())
        .arg("init")
        .assert()
        .success();
    // v2.0: every read requires an active session (or a presented macaroon).
    // Start one in the test fixture so individual tests don't have to.
    llms()
        .env("LLM_SECRETS_DIR", dir.path())
        .args(["session-start", "--ttl", "1h"])
        .assert()
        .success();
    dir
}

#[test]
fn init_creates_store() {
    let dir = fresh_store();
    assert!(dir.path().join("identity.txt").exists());
    assert!(dir.path().join("store.age").exists());

    llms()
        .env("LLM_SECRETS_DIR", dir.path())
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("secrets:      0"));
}

#[test]
fn init_refuses_to_overwrite() {
    let dir = fresh_store();
    llms()
        .env("LLM_SECRETS_DIR", dir.path())
        .arg("init")
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists"));
}

#[test]
fn set_list_peek_delete_round_trip() {
    let dir = fresh_store();
    let env_dir = dir.path();

    // set via stdin
    llms()
        .env("LLM_SECRETS_DIR", env_dir)
        .args(["set", "db_password", "--stdin"])
        .write_stdin("hunter2hunter2")
        .assert()
        .success();

    // list shows the key
    llms()
        .env("LLM_SECRETS_DIR", env_dir)
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("db_password"));

    // peek returns a masked value, NOT the plaintext
    llms()
        .env("LLM_SECRETS_DIR", env_dir)
        .args(["peek", "db_password"])
        .assert()
        .success()
        .stdout(predicate::str::contains("hunter2hunter2").not())
        .stdout(predicate::str::contains("*"));

    // delete with --force
    llms()
        .env("LLM_SECRETS_DIR", env_dir)
        .args(["delete", "db_password", "--force"])
        .assert()
        .success();

    llms()
        .env("LLM_SECRETS_DIR", env_dir)
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("(empty)"));
}

#[test]
fn exec_injects_secret_into_child_env() {
    let dir = fresh_store();
    let env_dir = dir.path();

    llms()
        .env("LLM_SECRETS_DIR", env_dir)
        .args(["set", "api_key", "--stdin"])
        .write_stdin("sk-test-12345")
        .assert()
        .success();

    // The child sees the secret in its env. The parent's stdout never
    // contained the plaintext — only the child's printf does.
    llms()
        .env("LLM_SECRETS_DIR", env_dir)
        .args([
            "exec",
            "--inject",
            "API=api_key",
            "--",
            "sh",
            "-c",
            "printf %s \"$API\"",
        ])
        .assert()
        .success()
        .stdout(predicate::str::diff("sk-test-12345"));
}

#[test]
fn peek_on_missing_key_errors() {
    let dir = fresh_store();
    llms()
        .env("LLM_SECRETS_DIR", dir.path())
        .args(["peek", "nonexistent"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found"));
}

#[test]
fn list_without_init_errors() {
    let dir = tempfile::tempdir().unwrap();
    llms()
        .env("LLM_SECRETS_DIR", dir.path())
        .arg("list")
        .assert()
        .failure()
        .stderr(predicate::str::contains("init"));
}

#[test]
fn session_start_and_info_round_trip() {
    let dir = tempfile::tempdir().unwrap();

    llms()
        .env("LLM_SECRETS_DIR", dir.path())
        .args(["session-start", "--ttl", "1h"])
        .assert()
        .success()
        .stdout(predicate::str::contains("session started"))
        .stdout(predicate::str::contains("expires at"));

    // v2.0: session.json IS a macaroon. root.key is the HMAC root.
    assert!(dir.path().join("session.json").exists());
    assert!(dir.path().join("root.key").exists());

    llms()
        .env("LLM_SECRETS_DIR", dir.path())
        .arg("session-info")
        .assert()
        .success()
        .stdout(predicate::str::contains("status:    active"));
}

#[test]
fn lease_grant_list_and_revoke() {
    let dir = fresh_store();
    let env_dir = dir.path();

    // Need a session first.
    llms()
        .env("LLM_SECRETS_DIR", env_dir)
        .args(["session-start", "--ttl", "1h"])
        .assert()
        .success();

    // Grant a lease.
    llms()
        .env("LLM_SECRETS_DIR", env_dir)
        .args(["lease", "db_password", "--ttl", "5m"])
        .assert()
        .success()
        .stdout(predicate::str::contains("granted lease"));

    // It shows up in `leases`.
    llms()
        .env("LLM_SECRETS_DIR", env_dir)
        .arg("leases")
        .assert()
        .success()
        .stdout(predicate::str::contains("db_password"));

    // Audit log has the grant entry.
    llms()
        .env("LLM_SECRETS_DIR", env_dir)
        .arg("audit")
        .assert()
        .success()
        .stdout(predicate::str::contains("lease.grant"))
        .stdout(predicate::str::contains("db_password"));

    // Killswitch.
    llms()
        .env("LLM_SECRETS_DIR", env_dir)
        .arg("revoke-all")
        .assert()
        .success()
        .stdout(predicate::str::contains("revoked 1 leases"));

    // Leases empty afterwards, session gone.
    llms()
        .env("LLM_SECRETS_DIR", env_dir)
        .arg("leases")
        .assert()
        .success()
        .stdout(predicate::str::contains("(no active leases)"));

    llms()
        .env("LLM_SECRETS_DIR", env_dir)
        .arg("session-info")
        .assert()
        .failure();
}

#[test]
fn mcp_initialize_lists_tools_and_never_returns_plaintext() {
    let dir = fresh_store();
    let env_dir = dir.path();

    // Seed a secret so list_secrets has something to find.
    llms()
        .env("LLM_SECRETS_DIR", env_dir)
        .args(["set", "api_key", "--stdin"])
        .write_stdin("super-secret-do-not-leak")
        .assert()
        .success();

    // Pipeline of MCP requests on stdin: initialize, tools/list,
    // tools/call list_secrets, tools/call peek_secret.
    let input = [
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#,
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_secrets","arguments":{}}}"#,
        r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"peek_secret","arguments":{"key":"api_key"}}}"#,
    ]
    .join("\n");

    let output = llms()
        .env("LLM_SECRETS_DIR", env_dir)
        .arg("mcp")
        .write_stdin(input)
        .assert()
        .success();

    let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap();

    // Initialize advertised the protocol version.
    assert!(stdout.contains("protocolVersion"), "stdout: {stdout}");
    // tools/list returned our tools (no `get_secret`).
    assert!(stdout.contains("list_secrets"), "stdout: {stdout}");
    assert!(stdout.contains("peek_secret"), "stdout: {stdout}");
    assert!(!stdout.contains("get_secret"), "MCP exposed a get tool!");
    // list_secrets returned the key name.
    assert!(stdout.contains("api_key"));
    // peek_secret returned a mask, NOT the plaintext.
    assert!(
        !stdout.contains("super-secret-do-not-leak"),
        "MCP leaked plaintext: {stdout}"
    );
    assert!(stdout.contains("*"));
}

#[test]
fn macaroon_happy_path_and_denial() {
    let dir = fresh_store();
    let env_dir = dir.path();

    // Seed a secret + start a session.
    llms()
        .env("LLM_SECRETS_DIR", env_dir)
        .args(["set", "api_key", "--stdin"])
        .write_stdin("super-secret-12345")
        .assert()
        .success();
    llms()
        .env("LLM_SECRETS_DIR", env_dir)
        .args(["session-start", "--ttl", "1h"])
        .assert()
        .success();

    // Mint a macaroon scoped to api_key.
    let mint = llms()
        .env("LLM_SECRETS_DIR", env_dir)
        .args(["macaroon", "mint", "--secret", "api_key", "--ttl", "5m"])
        .assert()
        .success();
    let macaroon = String::from_utf8(mint.get_output().stdout.clone())
        .unwrap()
        .trim()
        .to_string();
    assert!(!macaroon.is_empty(), "macaroon mint produced no output");

    // Inspect — pure parse, must not touch the store.
    llms()
        .env("LLM_SECRETS_DIR", env_dir)
        .args(["macaroon", "inspect", "--macaroon", &macaroon])
        .assert()
        .success()
        .stdout(predicate::str::contains("secret == api_key"));

    // Verify against the matching key.
    llms()
        .env("LLM_SECRETS_DIR", env_dir)
        .args([
            "macaroon",
            "verify",
            "--macaroon",
            &macaroon,
            "--key",
            "api_key",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("ok"));

    // Happy path: peek with the macaroon — masked, not plaintext.
    llms()
        .env("LLM_SECRETS_DIR", env_dir)
        .args(["peek", "api_key", "--macaroon", &macaroon])
        .assert()
        .success()
        .stdout(predicate::str::contains("super-secret-12345").not())
        .stdout(predicate::str::contains("*"));

    // Happy path: exec via env var (the realistic agent flow).
    llms()
        .env("LLM_SECRETS_DIR", env_dir)
        .env("LLM_SECRETS_MACAROON", &macaroon)
        .args([
            "exec",
            "--inject",
            "K=api_key",
            "--",
            "sh",
            "-c",
            "printf %s \"$K\"",
        ])
        .assert()
        .success()
        .stdout(predicate::str::diff("super-secret-12345"));
}

#[test]
fn macaroon_scoped_to_other_secret_is_denied() {
    let dir = fresh_store();
    let env_dir = dir.path();

    llms()
        .env("LLM_SECRETS_DIR", env_dir)
        .args(["set", "db_password", "--stdin"])
        .write_stdin("hunter2")
        .assert()
        .success();
    llms()
        .env("LLM_SECRETS_DIR", env_dir)
        .args(["set", "api_key", "--stdin"])
        .write_stdin("not-this-one")
        .assert()
        .success();
    llms()
        .env("LLM_SECRETS_DIR", env_dir)
        .args(["session-start", "--ttl", "1h"])
        .assert()
        .success();

    // Mint a macaroon scoped to api_key only.
    let mint = llms()
        .env("LLM_SECRETS_DIR", env_dir)
        .args(["macaroon", "mint", "--secret", "api_key", "--ttl", "5m"])
        .assert()
        .success();
    let macaroon = String::from_utf8(mint.get_output().stdout.clone())
        .unwrap()
        .trim()
        .to_string();

    // Trying to use it for db_password must be denied.
    llms()
        .env("LLM_SECRETS_DIR", env_dir)
        .args(["peek", "db_password", "--macaroon", &macaroon])
        .assert()
        .failure()
        .stderr(predicate::str::contains("secret_eq"));
}

#[test]
fn revoke_all_invalidates_existing_macaroon() {
    let dir = fresh_store();
    let env_dir = dir.path();

    llms()
        .env("LLM_SECRETS_DIR", env_dir)
        .args(["set", "api_key", "--stdin"])
        .write_stdin("v")
        .assert()
        .success();
    llms()
        .env("LLM_SECRETS_DIR", env_dir)
        .args(["session-start", "--ttl", "1h"])
        .assert()
        .success();

    let mint = llms()
        .env("LLM_SECRETS_DIR", env_dir)
        .args(["macaroon", "mint", "--secret", "api_key", "--ttl", "5m"])
        .assert()
        .success();
    let macaroon = String::from_utf8(mint.get_output().stdout.clone())
        .unwrap()
        .trim()
        .to_string();

    // Works before revoke.
    llms()
        .env("LLM_SECRETS_DIR", env_dir)
        .args(["peek", "api_key", "--macaroon", &macaroon])
        .assert()
        .success();

    // Killswitch.
    llms()
        .env("LLM_SECRETS_DIR", env_dir)
        .arg("revoke-all")
        .assert()
        .success();

    // Same macaroon must now fail (root key gone).
    llms()
        .env("LLM_SECRETS_DIR", env_dir)
        .args(["peek", "api_key", "--macaroon", &macaroon])
        .assert()
        .failure();
}

#[test]
fn audit_with_no_entries_is_clean() {
    let dir = fresh_store();
    llms()
        .env("LLM_SECRETS_DIR", dir.path())
        .arg("audit")
        .assert()
        .success()
        .stdout(predicate::str::contains("(no audit entries)"));
}

#[test]
fn session_info_without_session_errors() {
    let dir = tempfile::tempdir().unwrap();
    llms()
        .env("LLM_SECRETS_DIR", dir.path())
        .arg("session-info")
        .assert()
        .failure();
}

#[test]
fn exec_with_missing_command_after_dash_dash_errors() {
    let dir = fresh_store();
    llms()
        .env("LLM_SECRETS_DIR", dir.path())
        .args(["exec", "--inject", "X=y"])
        .assert()
        .failure();
}
