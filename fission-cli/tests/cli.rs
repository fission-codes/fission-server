use anyhow::{bail, Result};
use once_cell::sync::Lazy;
use rexpect::{
    process::wait::WaitStatus,
    session::{Options, PtySession},
    spawn_with_options,
};
use std::{path::PathBuf, process::Command};

/// cargo always builds binaries before building the `[[test]]`s, so this should just exist
pub static CLI_BIN: Lazy<PathBuf> = Lazy::new(|| assert_cmd::cargo::cargo_bin("fission-cli"));

const REXPECT_OPTS: Options = Options {
    strip_ansi_escape_codes: true,
    timeout_ms: Some(2000),
};

pub struct Cli {
    pub session: PtySession,
}

impl Cli {
    pub fn run(cmd_fn: impl FnOnce(&mut Command) -> &mut Command) -> Result<Self> {
        let mut cmd = Command::new(CLI_BIN.as_os_str());
        cmd.arg("--no-colors");
        cmd_fn(&mut cmd);

        tracing::info!("Running a fission-cli process");

        let session = spawn_with_options(cmd, REXPECT_OPTS)?;

        Ok(Self { session })
    }

    pub fn expect(&mut self, output: impl AsRef<str>) -> Result<()> {
        let output = output.as_ref();
        tracing::info!(output, "Expecting to see output");
        self.session.exp_string(output)?;
        Ok(())
    }

    pub fn send_line(&mut self, input: impl AsRef<str>) -> Result<()> {
        let input = input.as_ref();
        tracing::info!(input, "Entering input");
        self.session.send(input)?;
        self.session.send("\r")?;
        self.session.flush()?;
        tracing::info!("Entered input");
        Ok(())
    }

    pub fn expect_eof(&mut self) -> Result<()> {
        tracing::info!("Waiting for the CLI process to exit");
        self.session.exp_eof()?;
        tracing::info!("CLI process exited");
        Ok(())
    }

    pub fn expect_success(&mut self) -> Result<()> {
        self.expect_eof()?;
        match self.session.process.status() {
            Some(WaitStatus::Exited(_, 0)) => Ok(()),
            Some(WaitStatus::Exited(_, code)) => {
                bail!("Expected successful exit, but got status code {code}")
            }
            Some(status) => bail!("Expected successful exit, but got {status:?}"),
            None => bail!("Expected successful exit, but couldn't fetch process status"),
        }
    }
}
