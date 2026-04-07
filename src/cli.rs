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
        Command::SessionStart { ttl } => {
            println!("TODO: start session (ttl={ttl})");
            Ok(())
        }
        Command::SessionInfo => {
            println!("TODO: show session info");
            Ok(())
        }
        Command::Lease { key, ttl } => {
            println!("TODO: create lease for {key} (ttl={ttl})");
            Ok(())
        }
        Command::Leases => {
            println!("TODO: list active leases");
            Ok(())
        }
        Command::Audit { json, last } => {
            println!("TODO: show audit log (json={json}, last={last})");
            Ok(())
        }
        Command::RevokeAll { rotate } => {
            println!("TODO: revoke all leases (rotate={rotate})");
            Ok(())
        }
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
    let identity = store::load_identity()?;
    let store = store::load_store(&identity)?;
    let value = store
        .get(key)
        .ok_or_else(|| Error::KeyNotFound(key.to_string()))?;
    println!("{}", store::mask(value, chars));
    Ok(())
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
        let value = store
            .get(secret_key)
            .ok_or_else(|| Error::KeyNotFound(secret_key.to_string()))?;
        process.env(env_var, value);
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
