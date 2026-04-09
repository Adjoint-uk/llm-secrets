mod agent;
mod cli;
mod error;
mod lease;
mod macaroon;
mod mcp;
mod policy;
mod profile;
mod store;

fn main() {
    if let Err(e) = cli::run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
