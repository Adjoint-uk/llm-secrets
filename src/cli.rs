use std::process::Command as ProcessCommand;

use clap::{Parser, Subcommand};
use dialoguer::{Confirm, Password, theme::ColorfulTheme};

use crate::error::{Error, Result};
use crate::store;

#[derive(Parser)]
#[command(
    name = "llms",
    about = "Workload identity for AI agents — capability delegation, not credential sharing",
    long_about = "\
llm-secrets — workload identity for AI coding agents.

You don't *give* your AI agent your credentials. You *delegate* a slice of
your identity to it — narrowed to one secret, one repo, one branch, five
minutes — using an attenuated, signed bearer token (a macaroon). The agent
can use what you've given it. It cannot widen the grant. It cannot escalate.

Secrets never leave the binary as plaintext on stdout. There is no `get`
command. Architectural enforcement, not behavioural.

DAILY WORKFLOW

  llms set db_password               # store a secret (hidden input)
  llms list                          # see what you have
  llms peek db_password              # auto-creates a session if needed

  # Optional: explicit session for longer TTL or fresh root key
  llms session-start --ttl 8h

DELEGATE TO AN AGENT — THE MANUAL WAY

  M=$(llms macaroon mint \\
      --secret db_password \\
      --ttl 5m \\
      --branch main \\
      --agent claude-code)
  LLM_SECRETS_MACAROON=$M claude

  # The agent now holds a token narrowed to db_password, 5 min, this branch,
  # this agent. Removing or substituting any caveat invalidates the HMAC
  # chain. It can do less than you can — never more.

DELEGATE TO AN AGENT — THE EASY WAY (PROFILES, v2.1+)

  # ~/.config/llm-secrets/profiles.toml:
  #   [claude-db]
  #   secrets = [\"db_password\"]
  #   ttl     = \"5m\"
  #   branch  = \"main\"
  #   agent   = \"claude-code\"
  #   [claude-db.env]
  #   DB_PASS = \"db_password\"

  eval \"$(llms profile mint claude-db)\"     # mint and export
  claude                                       # agent inherits the token

  # Or in one step:
  llms profile exec claude-db -- psql -U admin mydb

  # Profiles ARE macaroons under the hood — they just save you typing the
  # caveat list every day. Same crypto, same enforcement.

INSPECT, AUDIT, REVOKE

  llms macaroon inspect --macaroon $M    # what does this token allow?
  llms audit --last 20                   # what did the agent touch?
  llms revoke-all                        # killswitch — every token dies in O(1)
  llms revoke-all --rotate               # also re-encrypt the store

For per-command help, run `llms <command> --help`. Start with:
  llms macaroon --help     (capability delegation — the headline)
  llms profile --help      (recipes for the same)
",
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
    #[command(long_about = "\
Run a child process with secrets injected as environment variables. The
parent process never holds plaintext for longer than is needed to populate
the child's env block. The plaintext never appears on stdout.

Two forms:

  # Manual injection — explicit ENV=key mappings
  llms exec --inject DB_PASS=db_password --inject API=api_key -- psql ...

  # Profile injection — read the env mapping from a TOML profile
  llms exec --profile iba -- iba-jira list

The profile form is the v2.1 ergonomic. It mints a fresh macaroon from
the profile's caveats and uses the profile's [env] table to drive the
ENV=key mappings. Equivalent to `llms profile exec`.
")]
    Exec {
        /// Secret mappings: ENV_VAR=secret_key (required unless --profile is given)
        #[arg(short, long)]
        inject: Vec<String>,
        /// Use a TOML profile (alias for `llms profile exec <name>`).
        /// Mints a fresh macaroon from the profile and injects its env map.
        #[arg(long, conflicts_with = "inject", conflicts_with = "macaroon")]
        profile: Option<String>,
        /// Override the profile's default TTL (only valid with --profile)
        #[arg(long, requires = "profile")]
        ttl: Option<String>,
        /// Present a macaroon (also honoured: $LLM_SECRETS_MACAROON)
        #[arg(long)]
        macaroon: Option<String>,
        /// Command to run
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },

    /// Check store status and dependencies
    Status,

    /// Start a session (or refresh the current one with a new TTL)
    ///
    /// Optional for basic use — reads auto-create a 1h session if needed.
    /// Use this to set a longer TTL or force a fresh root key.
    #[command(name = "session-start")]
    SessionStart {
        /// Session TTL (e.g., 1h, 30m)
        #[arg(long, default_value = "1h")]
        ttl: String,
    },

    /// Show current session identity and attestation
    #[command(name = "session-info")]
    SessionInfo,

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

    /// Mint, inspect, and verify delegated capability tokens (macaroons)
    #[command(long_about = "\
Macaroons are the headline. They are signed, attenuated, time-bounded
bearer tokens that let you delegate a slice of your identity to an AI
agent without handing over your full credentials.

Every caveat (secret, ttl, repo, branch, agent, who) is enforced by an
HMAC-SHA256 chain rooted in the per-session key. Removing, substituting,
or reordering any caveat breaks the chain. Verification needs only the
root key + the full caveat list — no oracle, no daemon, no network.

Revocation is one command: `llms revoke-all` deletes the root key, every
issued macaroon (and its delegated children) becomes unverifiable in O(1).

EXAMPLES

  # Narrow grant: one secret, 5 minutes, only on this branch and agent.
  M=$(llms macaroon mint \\
      --secret db_password --ttl 5m \\
      --branch main --agent claude-code)
  LLM_SECRETS_MACAROON=$M claude

  # Multiple secrets in one token (becomes a `secrets_in [...]` caveat).
  llms macaroon mint --secret db_password --secret api_key --ttl 1h

  # Inspect a token someone gave you (pure parse, never touches the store).
  llms macaroon inspect --macaroon $M

  # Verify the token is currently valid in this context.
  llms macaroon verify --macaroon $M --key db_password
")]
    Macaroon {
        #[command(subcommand)]
        action: MacaroonCommand,
    },

    /// Profile-driven mint and exec from ~/.config/llm-secrets/profiles.toml
    #[command(long_about = "\
Profiles are TOML recipes that group secrets, env-var mappings, and
default caveats under a name. They are CONFIG, not tokens. The macaroon
they produce at use time is the unforgeable, time-bounded thing.

Two layers, two concerns:
  - Profile (TOML, editable, dotfile-managed): the recipe.
  - Macaroon (signed, in-memory, short-lived):  the capability.

Stealing a profiles.toml gets you a list of secret NAMES. No access.
The macaroon is the only thing that ever carries authority, and it is
always narrow and short-lived.

PROFILE FILE LAYOUT (~/.config/llm-secrets/profiles.toml)

  [iba]
  secrets = [\"iba_ad_username\", \"iba_ad_password\", \"iba_jira_api_key\"]
  ttl     = \"8h\"
  agent   = \"claude-code\"     # optional caveat
  branch  = \"main\"            # optional caveat
  repo    = \"adjoint-uk/llm-secrets\"  # optional caveat

  [iba.env]
  IBA_AD_USERNAME = \"iba_ad_username\"
  IBA_AD_PASSWORD = \"iba_ad_password\"
  IBA_JIRA_TOKEN  = \"iba_jira_api_key\"

EXAMPLES

  llms profile list                          # what's defined?
  llms profile show iba                      # secrets, env, caveats
  llms profile exec iba -- iba-jira list     # mint + exec in one step
  eval \"$(llms profile mint iba)\"            # mint into shell env
  llms exec --profile iba -- ./deploy.sh     # alias for `profile exec`

WHEN TO USE PROFILES VS MANUAL MACAROON MINT

  Profile:  same delegation pattern repeated daily. Eliminates wrapper
            scripts and repeated `--secret X --ttl Y --branch Z` typing.
  Manual:   one-off task, exploring, custom caveats not in any profile,
            or when you want to be explicit about every constraint.

  The macaroon under both paths is the same shape. Profiles are not a
  different security model — they are a typing-saver over the same primitive.
")]
    Profile {
        #[command(subcommand)]
        action: ProfileCommand,
    },
}

#[derive(Subcommand)]
enum ProfileCommand {
    /// List profiles defined in profiles.toml.
    List,
    /// Show a profile's secrets, env mapping, and caveats.
    Show {
        /// Profile name
        name: String,
    },
    /// Mint a macaroon from a profile and print it as an export line.
    Mint {
        /// Profile name
        name: String,
        /// Override the profile's default TTL
        #[arg(long)]
        ttl: Option<String>,
    },
    /// Mint a macaroon from a profile and exec a command with the profile's
    /// env mappings injected. Equivalent to `llms exec --profile <name>`.
    Exec {
        /// Profile name
        name: String,
        /// Override the profile's default TTL
        #[arg(long)]
        ttl: Option<String>,
        /// Command to run
        #[arg(last = true, required = true)]
        command: Vec<String>,
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
            profile,
            ttl,
            macaroon,
            command,
        } => {
            if let Some(name) = profile {
                cmd_profile_exec(&name, ttl, command)
            } else {
                if inject.is_empty() {
                    return Err(Error::Other(
                        "exec requires --inject ENV=key (or --profile <name>)".into(),
                    ));
                }
                cmd_exec(inject, macaroon, command)
            }
        }
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
        Command::Profile { action } => match action {
            ProfileCommand::List => cmd_profile_list(),
            ProfileCommand::Show { name } => cmd_profile_show(&name),
            ProfileCommand::Mint { name, ttl } => cmd_profile_mint(&name, ttl),
            ProfileCommand::Exec { name, ttl, command } => cmd_profile_exec(&name, ttl, command),
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
    let ctx = gate(key, &macaroon)?;
    let identity = store::load_identity()?;
    let store = store::load_store(&identity)?;
    let value = store
        .get(key)
        .ok_or_else(|| Error::KeyNotFound(key.to_string()))?;
    println!("{}", store::mask(value, chars));
    let _ = crate::lease::audit(
        if macaroon.is_some() || std::env::var("LLM_SECRETS_MACAROON").is_ok() {
            "peek.delegated"
        } else {
            "peek"
        },
        &ctx,
        None,
    );
    Ok(())
}

/// The v2.0 read gate: every operation that reads a secret value travels
/// through this. Returns the verified `Context` for downstream auditing.
///
/// 1. Build the current context from the environment.
/// 2. Run the optional policy file check.
/// 3. Verify a macaroon — either the **explicit** one passed via
///    `--macaroon`/`LLM_SECRETS_MACAROON` (the agent-delegation path), or
///    the dev's **root macaroon** loaded from `session.json` (the
///    direct-CLI path). One of the two must verify.
///
/// There is no "no macaroon" path. Every read goes through a verified
/// token. For the direct-CLI path (no explicit `--macaroon`), a 1h
/// session is silently auto-minted if none exists — so the user never
/// has to remember `session-start` for basic use.
fn gate<'a>(key: &'a str, flag: &Option<String>) -> Result<crate::macaroon::Context<'a>> {
    let ctx = crate::macaroon::Context::current(key);
    crate::policy::check_access(&ctx)?;

    let m = if let Some(encoded) = crate::macaroon::pick_macaroon(flag) {
        crate::macaroon::Macaroon::decode(&encoded)?
    } else {
        crate::macaroon::Macaroon::load_or_auto_mint()?
    };
    m.verify(&ctx)?;
    Ok(ctx)
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

    let delegated = macaroon.is_some() || std::env::var("LLM_SECRETS_MACAROON").is_ok();
    let event = if delegated {
        "exec.inject.delegated"
    } else {
        "exec.inject"
    };

    for spec in &inject {
        let (env_var, secret_key) = spec
            .split_once('=')
            .ok_or_else(|| Error::Other(format!("invalid --inject {spec:?}, expected ENV=key")))?;
        let ctx = gate(secret_key, &macaroon)?;
        let value = store
            .get(secret_key)
            .ok_or_else(|| Error::KeyNotFound(secret_key.to_string()))?;
        process.env(env_var, value);
        let _ = crate::lease::audit(event, &ctx, None);
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

// ---- session commands (v2.0: a session IS a root macaroon) ---------------

fn cmd_session_start(ttl: &str) -> Result<()> {
    let dur = crate::macaroon::parse_duration(ttl)?;
    std::fs::create_dir_all(crate::store::store_dir()?)?;

    // Mint a fresh root macaroon. This rotates the HMAC root key, gathers
    // current context as caveats, and saves the macaroon as session.json.
    let root = crate::macaroon::Macaroon::mint_root(dur)?;

    println!("session started");
    print_caveats(&root);
    Ok(())
}

fn cmd_session_info() -> Result<()> {
    let root = crate::macaroon::Macaroon::load_root()?;
    let ctx = crate::macaroon::Context::current("(none)");
    match root.verify(&ctx) {
        Ok(()) => println!("status:    active"),
        Err(e) => {
            println!("status:    INVALID — {e}");
            return Err(e);
        }
    }
    print_caveats(&root);
    Ok(())
}

fn print_caveats(m: &crate::macaroon::Macaroon) {
    for c in &m.caveats {
        println!("  - {}", c.describe());
    }
}

fn or_dash(s: &str) -> &str {
    if s.is_empty() { "-" } else { s }
}

// ---- lease + audit + killswitch ------------------------------------------

fn cmd_lease(key: &str, ttl: &str, macaroon: Option<String>) -> Result<()> {
    let _ctx = gate(key, &macaroon)?;
    let dur = crate::macaroon::parse_duration(ttl)?;
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
    let count = crate::lease::revoke_all()?;
    println!("revoked {count} leases, the root macaroon, and the macaroon root key");
    if rotate {
        crate::store::rotate_age_key()?;
        println!("re-encrypted store under a fresh age key");
    }
    Ok(())
}

// ---- macaroon (delegation) commands --------------------------------------

fn cmd_macaroon_mint(
    secret: Vec<String>,
    ttl: &str,
    repo: Option<String>,
    branch: Option<String>,
    agent: Option<String>,
    who: Option<String>,
) -> Result<()> {
    let dur = crate::macaroon::parse_duration(ttl)?;
    let mut extras: Vec<crate::macaroon::Caveat> = Vec::new();

    match secret.len() {
        0 => {
            return Err(Error::Other(
                "at least one --secret is required (a delegated token with no narrowing is just your root)".into(),
            ));
        }
        1 => extras.push(crate::macaroon::Caveat::SecretEq(
            secret.into_iter().next().unwrap(),
        )),
        _ => extras.push(crate::macaroon::Caveat::SecretsIn(secret)),
    }

    extras.push(crate::macaroon::Caveat::ExpiresAt(chrono::Utc::now() + dur));
    if let Some(r) = repo {
        extras.push(crate::macaroon::Caveat::RepoEq(r));
    }
    if let Some(b) = branch {
        extras.push(crate::macaroon::Caveat::BranchEq(b));
    }
    if let Some(a) = agent {
        extras.push(crate::macaroon::Caveat::AgentEq(a));
    }
    if let Some(w) = who {
        extras.push(crate::macaroon::Caveat::WhoEq(w));
    }

    // Delegation derives the child token from the dev's root macaroon.
    // The agent inherits a *narrower* slice of the dev's identity.
    let root = crate::macaroon::Macaroon::load_root()?;
    let child = root.delegate(extras)?;
    println!("{}", child.encode()?);
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
    let probe_key = key.as_deref().unwrap_or("(unspecified)");
    let ctx = crate::macaroon::Context::current(probe_key);
    m.verify(&ctx)?;
    println!(
        "ok — signature valid and all {} caveats hold",
        m.caveats.len()
    );
    Ok(())
}

// ---- profile commands (v2.1: TOML recipes → caveats → existing mint) ----

fn cmd_profile_list() -> Result<()> {
    let profiles = crate::profile::Profile::list()?;
    if profiles.is_empty() {
        println!("(no profiles)");
        return Ok(());
    }
    for p in &profiles {
        println!(
            "{:16}  {} secret(s), ttl {}",
            p.name,
            p.secrets.len(),
            crate::profile::format_duration(p.ttl)
        );
    }
    Ok(())
}

fn cmd_profile_show(name: &str) -> Result<()> {
    let p = crate::profile::Profile::load(name)?;
    println!("profile:  {}", p.name);
    println!("secrets:  {}", p.secrets.join(", "));
    if !p.env.is_empty() {
        let max = p.env.keys().map(|k| k.len()).max().unwrap_or(0);
        println!("env:");
        for (env, key) in &p.env {
            println!("  {env:<max$} <- {key}");
        }
    }
    println!("ttl:      {}", crate::profile::format_duration(p.ttl));
    let extras: Vec<String> = [
        p.repo.as_ref().map(|r| format!("repo == {r}")),
        p.branch.as_ref().map(|b| format!("branch == {b}")),
        p.agent.as_ref().map(|a| format!("agent == {a}")),
    ]
    .into_iter()
    .flatten()
    .collect();
    if extras.is_empty() {
        println!("caveats:  (none beyond secrets+ttl)");
    } else {
        println!("caveats:  {}", extras.join(", "));
    }
    Ok(())
}

fn cmd_profile_mint(name: &str, ttl_override: Option<String>) -> Result<()> {
    let p = crate::profile::Profile::load(name)?;
    let ttl = ttl_override
        .as_deref()
        .map(crate::macaroon::parse_duration)
        .transpose()?;
    let root = crate::macaroon::Macaroon::load_or_auto_mint()?;
    let child = root.delegate(p.to_caveats(ttl))?;
    let encoded = child.encode()?;
    println!("export LLM_SECRETS_MACAROON={encoded}");
    let ctx = crate::macaroon::Context::current("(profile)");
    let _ = crate::lease::audit("profile.mint", &ctx, Some(format!("profile={}", p.name)));
    Ok(())
}

fn cmd_profile_exec(name: &str, ttl_override: Option<String>, command: Vec<String>) -> Result<()> {
    if command.is_empty() {
        return Err(Error::Other("no command provided after `--`".into()));
    }
    let p = crate::profile::Profile::load(name)?;
    if p.env.is_empty() {
        return Err(Error::Other(format!(
            "profile '{}' has no [env] mappings — nothing to inject",
            p.name
        )));
    }
    let ttl = ttl_override
        .as_deref()
        .map(crate::macaroon::parse_duration)
        .transpose()?;
    let root = crate::macaroon::Macaroon::load_or_auto_mint()?;
    let child = root.delegate(p.to_caveats(ttl))?;
    let encoded = child.encode()?;

    let inject: Vec<String> = p
        .env
        .iter()
        .map(|(env_var, secret_key)| format!("{env_var}={secret_key}"))
        .collect();

    let ctx = crate::macaroon::Context::current("(profile)");
    let _ = crate::lease::audit(
        "profile.exec",
        &ctx,
        Some(format!("profile={} command={}", p.name, command[0])),
    );

    cmd_exec(inject, Some(encoded), command)
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
