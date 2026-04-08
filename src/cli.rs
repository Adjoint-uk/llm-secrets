use std::process::Command as ProcessCommand;

use clap::{Parser, Subcommand};
use dialoguer::{Confirm, Password, theme::ColorfulTheme};

use crate::error::{Error, Result};
use crate::store;

#[derive(Parser)]
#[command(
    name = "llms",
    about = "Workload identity for AI agents",
    long_about = "Prove who you are, access only what you should, for only as long as you need.\n\n\
        llm-secrets provides identity-based secret access for AI coding agents.\n\
        Secrets are never exposed to the LLM context — there is no 'get' command.",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Initialise a new secrets store with age encryption
    Init,

    /// List secret keys (names only, no values)
    List,

    /// Masked preview of a secret value
    Peek {
        /// Secret key name
        key: String,
        /// Number of characters to reveal at each end
        #[arg(short, long, default_value_t = 4)]
        chars: usize,
        /// Present a macaroon (also honoured: $LLM_SECRETS_MACAROON)
        #[arg(long)]
        macaroon: Option<String>,
    },

    /// Store a secret (hidden input — never in shell history)
    Set {
        /// Secret key name
        key: String,
        /// Read the value from stdin instead of prompting (useful for pipes
        /// and scripted setup). The trailing newline is stripped.
        #[arg(long)]
        stdin: bool,
    },

    /// Delete a secret
    Delete {
        /// Secret key name
        key: String,
        /// Skip confirmation prompt
        #[arg(long)]
        force: bool,
    },

    /// Run a command with secrets injected as environment variables
    Exec {
        /// Secret mappings: ENV_VAR=secret_key
        #[arg(short, long, required = true)]
        inject: Vec<String>,
        /// Present a macaroon (also honoured: $LLM_SECRETS_MACAROON)
        #[arg(long)]
        macaroon: Option<String>,
        /// Command to run
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },

    /// Check store status and dependencies
    Status,

    // --- v0.3: Agent Identity ---
    /// Start an authenticated agent session
    #[command(name = "session-start")]
    SessionStart {
        /// Session TTL (e.g., 1h, 30m)
        #[arg(long, default_value = "1h")]
        ttl: String,
    },

    /// Show current session identity and attestation
    #[command(name = "session-info")]
    SessionInfo,

    // --- v0.4: Temporal Enforcement ---
    /// Request a time-bounded lease for a secret
    Lease {
        /// Secret key name
        key: String,
        /// Lease duration (e.g., 5m, 1h)
        #[arg(long, default_value = "5m")]
        ttl: String,
        /// Present a macaroon (also honoured: $LLM_SECRETS_MACAROON)
        #[arg(long)]
        macaroon: Option<String>,
    },

    /// List active leases
    Leases,

    /// View audit log
    Audit {
        /// Output raw JSONL
        #[arg(long)]
        json: bool,
        /// Number of recent entries to show
        #[arg(short, long, default_value_t = 20)]
        last: usize,
    },

    /// Emergency: revoke all active leases
    #[command(name = "revoke-all")]
    RevokeAll {
        /// Also rotate the age keypair and re-encrypt all secrets
        #[arg(long)]
        rotate: bool,
    },

    /// Run as an MCP (Model Context Protocol) server on stdio. Exposes a
    /// safe subset of the CLI to AI agents — never returns plaintext.
    Mcp,

    /// Mint, inspect, and verify macaroons (delegated capability tokens).
    /// See `docs/adr/0006-macaroons.md`.
    Macaroon {
        #[command(subcommand)]
        action: MacaroonCommand,
    },
}

#[derive(Subcommand)]
enum MacaroonCommand {
    /// Mint a fresh macaroon scoped by the given caveats.
    /// Requires an active session (the macaroon's root key lives there).
    Mint {
        /// Restrict to one or more named secrets (repeatable).
        #[arg(short, long)]
        secret: Vec<String>,
        /// Token TTL (e.g. 5m, 1h). Default 5m.
        #[arg(long, default_value = "5m")]
        ttl: String,
        /// Restrict to a specific repo (e.g. acme/billing).
        #[arg(long)]
        repo: Option<String>,
        /// Restrict to a specific branch.
        #[arg(long)]
        branch: Option<String>,
        /// Restrict to a specific detected agent (e.g. claude-code).
        #[arg(long)]
        agent: Option<String>,
        /// Restrict to a specific user (matches session.who).
        #[arg(long)]
        who: Option<String>,
    },

    /// Decode and pretty-print a macaroon. Pure parse — never touches the
    /// secret store. Reads from `--macaroon`, `LLM_SECRETS_MACAROON`, or stdin.
    Inspect {
        #[arg(long)]
        macaroon: Option<String>,
    },

    /// Verify a macaroon's signature and check its caveats against the
    /// current session context. Exits 0 on pass, non-zero on fail.
    Verify {
        #[arg(long)]
        macaroon: Option<String>,
        /// Optional: pretend the request is for this secret key when
        /// evaluating per-key caveats like `secret_eq`.
        #[arg(long)]
        key: Option<String>,
    },
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Init => cmd_init(),
        Command::List => cmd_list(),
        Command::Peek {
            key,
            chars,
            macaroon,
        } => cmd_peek(&key, chars, macaroon),
        Command::Set { key, stdin } => cmd_set(&key, stdin),
        Command::Delete { key, force } => cmd_delete(&key, force),
        Command::Exec {
            inject,
            macaroon,
            command,
        } => cmd_exec(inject, macaroon, command),
        Command::Status => cmd_status(),
        Command::SessionStart { ttl } => cmd_session_start(&ttl),
        Command::SessionInfo => cmd_session_info(),
        Command::Lease { key, ttl, macaroon } => cmd_lease(&key, &ttl, macaroon),
        Command::Leases => cmd_leases(),
        Command::Audit { json, last } => cmd_audit(json, last),
        Command::RevokeAll { rotate } => cmd_revoke_all(rotate),
        Command::Mcp => crate::mcp::serve(),
        Command::Macaroon { action } => match action {
            MacaroonCommand::Mint {
                secret,
                ttl,
                repo,
                branch,
                agent,
                who,
            } => cmd_macaroon_mint(secret, &ttl, repo, branch, agent, who),
            MacaroonCommand::Inspect { macaroon } => cmd_macaroon_inspect(macaroon),
            MacaroonCommand::Verify { macaroon, key } => cmd_macaroon_verify(macaroon, key),
        },
    }
}

// ---- v0.2 command implementations -----------------------------------------

fn cmd_init() -> Result<()> {
    let (id_path, store_path) = store::init()?;
    println!("initialised");
    println!("  identity: {}", id_path.display());
    println!("  store:    {}", store_path.display());
    println!();
    println!("back up your identity file. without it, the store cannot be decrypted.");
    Ok(())
}

fn cmd_list() -> Result<()> {
    let identity = store::load_identity()?;
    let store = store::load_store(&identity)?;
    if store.len() == 0 {
        println!("(empty)");
        return Ok(());
    }
    for key in store.keys() {
        println!("{key}");
    }
    Ok(())
}

fn cmd_peek(key: &str, chars: usize, macaroon: Option<String>) -> Result<()> {
    crate::policy::check_access(key)?;
    check_macaroon(&macaroon, key)?;
    let identity = store::load_identity()?;
    let store = store::load_store(&identity)?;
    let value = store
        .get(key)
        .ok_or_else(|| Error::KeyNotFound(key.to_string()))?;
    println!("{}", store::mask(value, chars));
    audit_if_session(
        if macaroon_was_used(&macaroon) {
            "peek.macaroon"
        } else {
            "peek"
        },
        key,
    );
    Ok(())
}

/// If a macaroon is presented (via `--macaroon` or `LLM_SECRETS_MACAROON`),
/// verify its signature against the active session's root key and check
/// every caveat against the request context. Returns Ok(()) if no macaroon
/// is presented at all (the v1.0 path is unchanged).
///
/// **A macaroon never bypasses policy** — it can only further restrict.
/// Both checks must pass.
fn check_macaroon(flag: &Option<String>, key: &str) -> Result<()> {
    let Some(encoded) = crate::macaroon::pick_macaroon(flag) else {
        return Ok(());
    };
    let m = crate::macaroon::Macaroon::decode(&encoded)?;
    let session = crate::identity::active_session().map_err(|_| Error::PolicyDenied {
        key: key.to_string(),
        reason: "macaroon presented but no active session".into(),
    })?;
    let ctx = crate::macaroon::Context {
        key,
        claims: &session.claims,
    };
    m.verify(&ctx)
}

fn macaroon_was_used(flag: &Option<String>) -> bool {
    crate::macaroon::pick_macaroon(flag).is_some()
}

/// Best-effort audit. We deliberately swallow errors here so that audit
/// failures don't break the access path; the calling shell still sees the
/// secret. (`revoke-all` audits with stricter semantics.)
fn audit_if_session(event: &str, key: &str) {
    if let Ok(session) = crate::identity::active_session() {
        let _ = crate::lease::audit(event, key, &session.claims, None);
    }
}

fn cmd_set(key: &str, from_stdin: bool) -> Result<()> {
    let identity = store::load_identity()?;
    let mut store = store::load_store(&identity)?;

    let value: String = if from_stdin {
        use std::io::Read;
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| Error::Other(format!("stdin: {e}")))?;
        // Strip a single trailing newline so `echo foo | llms set` does the
        // intuitive thing. Internal newlines are preserved.
        if let Some(stripped) = buf.strip_suffix('\n') {
            buf = stripped.trim_end_matches('\r').to_string();
        }
        buf
    } else {
        Password::with_theme(&ColorfulTheme::default())
            .with_prompt(format!("value for {key}"))
            .with_confirmation("confirm", "values do not match")
            .interact()
            .map_err(|e| Error::Other(format!("input: {e}")))?
    };

    let existed = store.contains(key);
    store.insert(key.to_string(), value);
    store::save_store(&store, &identity.to_public())?;

    println!("{}: {}", if existed { "updated" } else { "stored" }, key);
    Ok(())
}

fn cmd_delete(key: &str, force: bool) -> Result<()> {
    let identity = store::load_identity()?;
    let mut store = store::load_store(&identity)?;

    if !store.contains(key) {
        return Err(Error::KeyNotFound(key.to_string()));
    }

    if !force {
        let confirmed = Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt(format!("delete {key}?"))
            .default(false)
            .interact()
            .map_err(|e| Error::Other(format!("input: {e}")))?;
        if !confirmed {
            println!("cancelled");
            return Ok(());
        }
    }

    store.remove(key)?;
    store::save_store(&store, &identity.to_public())?;
    println!("deleted: {key}");
    Ok(())
}

fn cmd_status() -> Result<()> {
    let dir = store::store_dir()?;
    let id = store::identity_path()?;
    let st = store::store_path()?;

    println!("store dir:    {}", dir.display());
    println!(
        "identity:     {}",
        if id.exists() {
            "present"
        } else {
            "missing — run `llms init`"
        }
    );
    println!(
        "store:        {}",
        if st.exists() {
            "present"
        } else {
            "missing — run `llms init`"
        }
    );

    if id.exists() && st.exists() {
        let identity = store::load_identity()?;
        let store = store::load_store(&identity)?;
        println!("secrets:      {}", store.len());
    }
    Ok(())
}

fn cmd_exec(inject: Vec<String>, macaroon: Option<String>, command: Vec<String>) -> Result<()> {
    if command.is_empty() {
        return Err(Error::Other("no command provided after `--`".into()));
    }

    let identity = store::load_identity()?;
    let store = store::load_store(&identity)?;

    let mut process = ProcessCommand::new(&command[0]);
    process.args(&command[1..]);

    for spec in &inject {
        let (env_var, secret_key) = spec
            .split_once('=')
            .ok_or_else(|| Error::Other(format!("invalid --inject {spec:?}, expected ENV=key")))?;
        crate::policy::check_access(secret_key)?;
        check_macaroon(&macaroon, secret_key)?;
        let value = store
            .get(secret_key)
            .ok_or_else(|| Error::KeyNotFound(secret_key.to_string()))?;
        process.env(env_var, value);
        audit_if_session(
            if macaroon_was_used(&macaroon) {
                "exec.inject.macaroon"
            } else {
                "exec.inject"
            },
            secret_key,
        );
    }

    // Drop the decrypted store before exec'ing the child so plaintext lives
    // in this process for the minimum possible window.
    drop(store);

    let status = process
        .status()
        .map_err(|e| Error::Other(format!("could not spawn {:?}: {e}", command[0])))?;

    if !status.success() {
        let code = status.code().unwrap_or(1);
        std::process::exit(code);
    }
    Ok(())
}

// ---- v0.3 command implementations -----------------------------------------

fn cmd_session_start(ttl: &str) -> Result<()> {
    let dur = crate::identity::parse_duration(ttl)?;
    // Make sure the store dir exists, even if init hasn't run yet — sessions
    // can be opened independently.
    std::fs::create_dir_all(crate::store::store_dir()?)?;

    let claims = crate::identity::Claims::gather(dur);
    let session = crate::identity::Session::new(claims)?;
    crate::identity::save_session(&session)?;
    // Rotate the macaroon root key — invalidates any previously-derived
    // macaroons from the prior session.
    crate::macaroon::rotate_root_key()?;

    println!("session started");
    print_claims(&session);
    println!();
    println!("expires: {}", session.claims.expires_at.to_rfc3339());
    Ok(())
}

fn cmd_session_info() -> Result<()> {
    let session = crate::identity::load_session()?;
    match session.verify() {
        Ok(()) => println!("signature: valid"),
        Err(e) => {
            println!("signature: INVALID — {e}");
            return Err(e);
        }
    }
    if session.is_expired() {
        println!(
            "status:    EXPIRED at {}",
            session.claims.expires_at.to_rfc3339()
        );
    } else {
        println!(
            "status:    active until {}",
            session.claims.expires_at.to_rfc3339()
        );
    }
    print_claims(&session);
    Ok(())
}

fn print_claims(session: &crate::identity::Session) {
    let c = &session.claims;
    println!("  who:    {}", or_dash(&c.who));
    println!("  repo:   {}", or_dash(&c.repo));
    println!("  branch: {}", or_dash(&c.branch));
    println!("  agent:  {}", or_dash(&c.agent));
    println!("  pid:    {}", c.pid);
}

fn or_dash(s: &str) -> &str {
    if s.is_empty() { "-" } else { s }
}

// ---- v0.4 command implementations -----------------------------------------

fn cmd_lease(key: &str, ttl: &str, macaroon: Option<String>) -> Result<()> {
    crate::policy::check_access(key)?;
    check_macaroon(&macaroon, key)?;
    let dur = crate::identity::parse_duration(ttl)?;
    let lease = crate::lease::grant(key, dur)?;
    println!("granted lease for {key}");
    println!("  expires: {}", lease.expires_at.to_rfc3339());
    Ok(())
}

fn cmd_leases() -> Result<()> {
    let mut set = crate::lease::LeaseSet::load()?;
    let pruned = set.prune();
    if pruned > 0 {
        set.save()?;
    }
    if set.leases.is_empty() {
        println!("(no active leases)");
        return Ok(());
    }
    for l in &set.leases {
        println!(
            "{}  expires {}  by {}",
            l.key,
            l.expires_at.to_rfc3339(),
            or_dash(&l.session_who),
        );
    }
    Ok(())
}

fn cmd_audit(json: bool, last: usize) -> Result<()> {
    let entries = crate::lease::read_recent(last)?;
    if entries.is_empty() {
        println!("(no audit entries)");
        return Ok(());
    }
    if json {
        for e in &entries {
            println!(
                "{}",
                serde_json::to_string(e)
                    .map_err(|err| Error::Other(format!("audit serialise: {err}")))?
            );
        }
    } else {
        for e in &entries {
            println!(
                "{}  {:12}  {:20}  {}  {}",
                e.at.to_rfc3339(),
                e.event,
                e.key,
                or_dash(&e.who),
                e.note.as_deref().unwrap_or(""),
            );
        }
    }
    Ok(())
}

fn cmd_revoke_all(rotate: bool) -> Result<()> {
    if rotate {
        return Err(Error::Other(
            "--rotate is not implemented yet (planned for v1.0)".into(),
        ));
    }
    let count = crate::lease::revoke_all()?;
    crate::macaroon::delete_root_key()?;
    println!("revoked {count} leases, any active session, and macaroon root key");
    Ok(())
}

// ---- v1.1 macaroon command implementations -------------------------------

fn cmd_macaroon_mint(
    secret: Vec<String>,
    ttl: &str,
    repo: Option<String>,
    branch: Option<String>,
    agent: Option<String>,
    who: Option<String>,
) -> Result<()> {
    let dur = crate::identity::parse_duration(ttl)?;
    let mut caveats: Vec<crate::macaroon::Caveat> = Vec::new();

    match secret.len() {
        0 => {
            return Err(Error::Other(
                "at least one --secret is required (a macaroon with no scope is just a session)"
                    .into(),
            ));
        }
        1 => caveats.push(crate::macaroon::Caveat::SecretEq(
            secret.into_iter().next().unwrap(),
        )),
        _ => caveats.push(crate::macaroon::Caveat::SecretsIn(secret)),
    }

    caveats.push(crate::macaroon::Caveat::ExpiresAt(chrono::Utc::now() + dur));

    if let Some(r) = repo {
        caveats.push(crate::macaroon::Caveat::RepoEq(r));
    }
    if let Some(b) = branch {
        caveats.push(crate::macaroon::Caveat::BranchEq(b));
    }
    if let Some(a) = agent {
        caveats.push(crate::macaroon::Caveat::AgentEq(a));
    }
    if let Some(w) = who {
        caveats.push(crate::macaroon::Caveat::WhoEq(w));
    }

    let m = crate::macaroon::Macaroon::mint(caveats)?;
    println!("{}", m.encode()?);
    Ok(())
}

fn cmd_macaroon_inspect(macaroon: Option<String>) -> Result<()> {
    let encoded = read_macaroon_input(macaroon)?;
    let m = crate::macaroon::Macaroon::decode(&encoded)?;
    println!("id:        {}", m.id);
    println!("location:  {}", m.location);
    println!("caveats:");
    for c in &m.caveats {
        println!("  - {}", c.describe());
    }
    println!("signature: {}", m.signature);
    println!();
    println!("(this is a pure parse — the secret store was never touched)");
    Ok(())
}

fn cmd_macaroon_verify(macaroon: Option<String>, key: Option<String>) -> Result<()> {
    let encoded = read_macaroon_input(macaroon)?;
    let m = crate::macaroon::Macaroon::decode(&encoded)?;
    let session = crate::identity::active_session()?;
    let probe_key = key.as_deref().unwrap_or("(unspecified)");
    let ctx = crate::macaroon::Context {
        key: probe_key,
        claims: &session.claims,
    };
    m.verify(&ctx)?;
    println!(
        "ok — signature valid and all {} caveats hold",
        m.caveats.len()
    );
    Ok(())
}

/// Read a macaroon from `--macaroon`, or `LLM_SECRETS_MACAROON`, or stdin
/// (in that order). Used by `inspect` and `verify`.
fn read_macaroon_input(flag: Option<String>) -> Result<String> {
    if let Some(s) = crate::macaroon::pick_macaroon(&flag) {
        return Ok(s);
    }
    use std::io::Read;
    let mut buf = String::new();
    std::io::stdin()
        .read_to_string(&mut buf)
        .map_err(|e| Error::Other(format!("stdin: {e}")))?;
    let trimmed = buf.trim().to_string();
    if trimmed.is_empty() {
        return Err(Error::Other(
            "no macaroon provided (use --macaroon, LLM_SECRETS_MACAROON, or stdin)".into(),
        ));
    }
    Ok(trimmed)
}
