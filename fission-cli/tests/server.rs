use anyhow::{anyhow, bail, Result};
use escargot::CargoRun;
use once_cell::sync::Lazy;
use std::{
    io::{stdout, BufRead, BufReader, Read, Write},
    process::{Child, ChildStdout, Stdio},
    sync::{Mutex, MutexGuard},
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

static LOCK: Mutex<()> = Mutex::new(());

#[must_use]
pub struct FissionServer<'a> {
    process: Child,
    _guard: MutexGuard<'a, ()>,
}

impl FissionServer<'_> {
    pub fn spawn<'s>(scope: &'s Scope<'s, '_>) -> Result<Self> {
        tracing::info!("Waiting for server lock");
        let _guard = LOCK.lock().map_err(|_| anyhow!("Failed locking"))?;
        tracing::info!("Aquired server lock");

        let mut process = SERVER_BIN
            .command()
            .arg("--close-on-stdin-close")
            .arg("--no-colors")
            .arg("--ephemeral-db")
            .stdout(Stdio::piped())
            .spawn()?;

        // Take ownership of stdout
        let mut child_stdout = process
            .stdout
            .take()
            .ok_or(anyhow!("no fission-server stdout"))?;

        // Wait for the server to start listening on a port
        tracing::info!("Waiting for the fission server API to be ready for requests");
        read_until(&mut child_stdout, "Application server listening")?;

        // Then spawn a scoped thread to reprint everything to current system stdout:
        reprint_stdout(scope, child_stdout)?;

        tracing::info!("Server ready.");
        Ok(Self { process, _guard })
    }
}

impl Drop for FissionServer<'_> {
    fn drop(&mut self) {
        tracing::info!("Killing the fission server process");
        if let Err(e) = self.process.kill() {
            eprintln!("Error trying to kill the fission server process: {e:?}");
        }
    }
}

pub fn listen_email<'s>(
    scope: &'s Scope<'s, '_>,
    email: &str,
) -> ScopedJoinHandle<'s, Result<String>> {
    use websocket::{sync::client::*, OwnedMessage};

    let relay = format!("ws://localhost:3000/api/v0/relay/{email}");

    tracing::info!("Spawning thread to listen for emails to {email}");
    scope.spawn(move || {
        let mut client = ClientBuilder::new(&relay)?.connect_insecure()?;
        loop {
            if let OwnedMessage::Text(code) = client.recv_message()? {
                return Ok(code);
            }
        }
    })
}

fn read_until(read: &mut impl std::io::Read, line_contains: &str) -> Result<()> {
    let mut reader = BufReader::new(read);
    let line = &mut String::new();
    loop {
        line.clear();
        let read = reader.read_line(line)?;
        if read == 0 {
            bail!("read_util: {line_contains:?} never appeared");
        }

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
