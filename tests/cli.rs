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
