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
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Init => cmd_init(),
        Command::List => cmd_list(),
        Command::Peek { key, chars } => cmd_peek(&key, chars),
        Command::Set { key, stdin } => cmd_set(&key, stdin),
        Command::Delete { key, force } => cmd_delete(&key, force),
        Command::Exec { inject, command } => cmd_exec(inject, command),
        Command::Status => cmd_status(),
        Command::SessionStart { ttl } => cmd_session_start(&ttl),
        Command::SessionInfo => cmd_session_info(),
        Command::Lease { key, ttl } => cmd_lease(&key, &ttl),
        Command::Leases => cmd_leases(),
        Command::Audit { json, last } => cmd_audit(json, last),
        Command::RevokeAll { rotate } => cmd_revoke_all(rotate),
        Command::Mcp => crate::mcp::serve(),
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

fn cmd_peek(key: &str, chars: usize) -> Result<()> {
    crate::policy::check_access(key)?;
    let identity = store::load_identity()?;
    let store = store::load_store(&identity)?;
    let value = store
        .get(key)
        .ok_or_else(|| Error::KeyNotFound(key.to_string()))?;
    println!("{}", store::mask(value, chars));
    audit_if_session("peek", key);
    Ok(())
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

fn cmd_exec(inject: Vec<String>, command: Vec<String>) -> Result<()> {
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
        let value = store
            .get(secret_key)
            .ok_or_else(|| Error::KeyNotFound(secret_key.to_string()))?;
        process.env(env_var, value);
        audit_if_session("exec.inject", secret_key);
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

fn cmd_lease(key: &str, ttl: &str) -> Result<()> {
    crate::policy::check_access(key)?;
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
    println!("revoked {count} leases and any active session");
    Ok(())
}
