mod agent;
mod cli;
mod error;
mod identity;
mod policy;
mod store;

fn main() {
    if let Err(e) = cli::run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
