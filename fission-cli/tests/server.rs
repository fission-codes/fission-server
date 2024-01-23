use anyhow::{anyhow, bail, Result};
use escargot::CargoRun;
use once_cell::sync::Lazy;
use std::{
    io::{BufRead, BufReader, Read},
    process::{Child, Stdio},
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
        let _guard = LOCK
            .lock()
            .map_err(|_| anyhow!("Failed locking server lock"))?;
        tracing::info!("Aquired server lock");

        let rust_log = std::env::var("RUST_LOG")
            .ok()
            .map_or("fission_server=info".into(), |rl| {
                format!("{rl},fission_server=info")
            });

        let mut process = SERVER_BIN
            .command()
            .arg("--no-colors")
            .arg("--ephemeral-db")
            .arg("--gen-key-if-needed")
            .env("RUST_LOG", rust_log)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        // Take ownership of outputs
        let mut child_stdout = process
            .stdout
            .take()
            .ok_or(anyhow!("no fission-server stdout"))?;

        let child_stderr = process
            .stderr
            .take()
            .ok_or(anyhow!("no fission-server stderr"))?;

        // immediately start reprinting stderr
        // We use print/eprint because that gets captured nicely by `cargo test`.
        process_lines(scope, child_stderr, |line| eprint!("{line}"))?;

        // Wait for the server to start listening on a port
        tracing::info!("Waiting for the fission server API to be ready for requests");
        read_until(&mut child_stdout, "Application server listening")?;

        // Then spawn a scoped thread to reprint stdout:
        process_lines(scope, child_stdout, |line| print!("{line}"))?;

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

        print!("{line}");
        if line.contains(line_contains) {
            return Ok(());
        }
    }
}

fn process_lines<'scope>(
    scope: &'scope Scope<'scope, '_>,
    output: impl Read + Send + 'scope,
    action: impl Fn(&String) -> () + Send + 'scope,
) -> Result<ScopedJoinHandle<'scope, Result<()>>> {
    let mut reader = BufReader::new(output);
    let mut line = String::new();
    Ok(scope.spawn(move || loop {
        line.clear();
        let bytes_read = reader.read_line(&mut line)?;

        // If bytes_read is 0, it indicates EOF.
        if bytes_read == 0 {
            return Ok::<(), anyhow::Error>(());
        }

        action(&line);
    }))
}
