//! Run via `cargo test -p fission-cli --test integration`
use crate::server::FissionServer;
use assert_cmd::assert::OutputAssertExt as _;
use once_cell::sync::Lazy;
use predicates::str::contains;
use std::{path::PathBuf, process::Command, thread::scope};
use testresult::TestResult;

mod server;

/// cargo always builds binaries before building the `[[test]]`s, so this should just exist
static CLI_BIN: Lazy<PathBuf> = Lazy::new(|| assert_cmd::cargo::cargo_bin("fission-cli"));

#[test_log::test]
fn test_cli_helptext() -> TestResult {
    Command::new(CLI_BIN.as_os_str())
        .arg("--no-colors")
        .arg("help")
        .assert()
        .try_success()?
        .try_stdout(contains("fission-cli"))?
        .try_stdout(contains("account"))?
        .try_stdout(contains("paths"))?
        .try_stdout(contains("help"))?
        .try_stdout(contains("--key-file"))?;

    Ok(())
}

#[test_log::test]
fn test_cli_account_helptext() -> TestResult {
    Command::new(CLI_BIN.as_os_str())
        .arg("--no-colors")
        .arg("account")
        .arg("--help")
        .assert()
        .try_success()?
        .try_stdout(contains("fission-cli"))?
        .try_stdout(contains("create"))?
        .try_stdout(contains("login"))?
        .try_stdout(contains("list"))?
        .try_stdout(contains("rename"))?
        .try_stdout(contains("delete"))?
        .try_stdout(contains("help"))?;

    Ok(())
}

#[test_log::test]
fn test_ci_account_list() -> TestResult {
    scope(|s| {
        let _server = FissionServer::spawn(s)?;

        Command::new(CLI_BIN.as_os_str())
            .arg("--no-colors")
            .arg("account")
            .arg("list")
            .assert()
            .try_success()?
            .try_stdout(contains("You don't have access to any accounts yet"))?;

        Ok(())
    })
}
