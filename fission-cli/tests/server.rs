use anyhow::{anyhow, Result};
use escargot::CargoRun;
use once_cell::sync::Lazy;
use std::{
    io::{stdout, BufRead, BufReader, Read, Write},
    process::{Child, ChildStdout, Stdio},
    thread::{Scope, ScopedJoinHandle},
};

static SERVER_BIN: Lazy<CargoRun> = Lazy::new(|| {
    // let temp = assert_fs::TempDir::new().expect("Couldn't create temporary directory");
    tracing::info!("Possibly starting a fission-server build");
    let cargo_run = escargot::CargoBuild::new()
        .bin("fission-server")
        .current_target()
        .manifest_path("../fission-server/Cargo.toml")
        .run()
        .expect("fission-server binary build failed");
    tracing::info!(path = ?cargo_run.path(), exists = ?cargo_run.path().exists(), "fission-server binary ready");
    cargo_run
});

pub struct FissionServer {
    process: Child,
}

impl FissionServer {
    pub fn spawn<'s>(scope: &'s Scope<'s, '_>) -> Result<Self> {
        let mut process = SERVER_BIN
            .command()
            .arg("--close-on-stdin-close")
            .arg("--no-colors")
            .stdout(Stdio::piped())
            .spawn()?;

        // Take ownership of stdout
        let mut child_stdout = process
            .stdout
            .take()
            .ok_or(anyhow!("no fission-server stdout"))?;

        // Wait for the server to start listening on a port
        read_until(&mut child_stdout, "Application server listening")?;

        // Then spawn a scoped thread to reprint everything to current system stdout:
        reprint_stdout(scope, child_stdout)?;

        Ok(Self { process })
    }
}

impl Drop for FissionServer {
    fn drop(&mut self) {
        tracing::info!("Killing the fission server process");
        if let Err(e) = self.process.kill() {
            eprintln!("Error trying to kill the fission server process: {e:?}");
        }
    }
}

fn read_until(read: &mut impl std::io::Read, line_contains: &str) -> Result<()> {
    let mut reader = BufReader::new(read);
    let line = &mut String::new();
    loop {
        line.clear();
        reader.read_line(line)?;
        stdout().lock().write_all(line.as_bytes())?;
        if line.contains(line_contains) {
            return Ok(());
        }
    }
}

fn reprint_stdout<'scope>(
    scope: &'scope Scope<'scope, '_>,
    mut child_stdout: ChildStdout,
) -> Result<ScopedJoinHandle<'scope, Result<()>>> {
    Ok(scope.spawn(move || loop {
        let mut buf = [0u8; 4096];
        let bytes_read = child_stdout.read(&mut buf)?;

        // If bytes_read is 0, it indicates EOF.
        if bytes_read == 0 {
            return Ok::<(), anyhow::Error>(());
        }

        stdout().lock().write_all(&buf[0..bytes_read])?;
    }))
}
