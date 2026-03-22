use clap::{Parser, Subcommand};

use crate::error::Result;

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
        Command::Init => {
            println!("TODO: initialise age keypair and secrets store");
            Ok(())
        }
        Command::List => {
            println!("TODO: list secret keys");
            Ok(())
        }
        Command::Peek { key, chars } => {
            println!("TODO: peek at {key} (showing {chars} chars)");
            Ok(())
        }
        Command::Set { key } => {
            println!("TODO: set secret {key}");
            Ok(())
        }
        Command::Delete { key, force } => {
            println!("TODO: delete {key} (force={force})");
            Ok(())
        }
        Command::Exec { inject, command } => {
            println!("TODO: exec {:?} with inject {:?}", command, inject);
            Ok(())
        }
        Command::Status => {
            println!("TODO: show status");
            Ok(())
        }
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
