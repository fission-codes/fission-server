//! Run via `cargo test -p fission-cli --test integration`
use crate::{
    cli::{Cli, CLI_BIN},
    server::FissionServer,
};
use assert_cmd::assert::OutputAssertExt as _;
use predicates::{boolean::PredicateBooleanExt as _, str::contains};
use std::{process::Command, thread::scope};
use testresult::TestResult;

mod cli;
mod server;

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
        .try_stdout(contains("--key-file"))?
        .try_stdout(contains("--key-seed").not())?;

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
fn test_cli_account_list() -> TestResult {
    scope(|s| {
        let _server = FissionServer::spawn(s)?;

        Command::new(CLI_BIN.as_os_str())
            .arg("--no-colors")
            .arg("--key-seed")
            .arg("test_cli_account_list")
            .arg("account")
            .arg("list")
            .assert()
            .try_success()?
            .try_stdout(contains("You don't have access to any accounts yet"))?;

        Ok(())
    })
}

#[test_log::test]
fn test_cli_account_create() -> TestResult {
    scope(|s| {
        let server = FissionServer::spawn(s)?;

        let email = "mail@example.test";
        let email_inbox = server.listen_email(s, email);

        let mut cli = Cli::run(|cmd| {
            cmd.arg("--key-seed=test_cli_account_create")
                .arg("account")
                .arg("create")
        })?;

        cli.expect("What's your email address?")?;
        cli.send_line(email)?;
        cli.expect("Successfully requested an email verification code")?;

        let code = email_inbox.join().map_err(|_| "thread panicked")??;
        cli.send_line(&code)?;
        cli.expect("Choose a username")?;
        cli.send_line("example")?;
        cli.expect("Successfully created your account")?;
        cli.expect_success()?;

        Ok(())
    })
}
