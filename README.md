<div align="center">
  <a href="https://github.com/fission-codes/fission-server" target="_blank">
    <img src="https://raw.githubusercontent.com/fission-codes/fission-server/main/assets/a_logo.png" alt="fission-server Logo" width="100"></img>
  </a>

  <h1 align="center">fission-server</h1>

  <p>
    <a href="https://crates.io/crates/fission-server">
      <img src="https://img.shields.io/crates/v/fission-server?label=crates" alt="Crate">
    </a>
    <a href="https://codecov.io/gh/fission-codes/fission-server">
      <img src="https://codecov.io/gh/fission-codes/fission-server/branch/main/graph/badge.svg?token=SOMETOKEN" alt="Code Coverage"/>
    </a>
    <a href="https://github.com/fission-codes/fission-server/actions?query=">
      <img src="https://github.com/fission-codes/fission-server/actions/workflows/tests_and_checks.yml/badge.svg" alt="Build Status">
    </a>
    <a href="https://github.com/fission-codes/fission-server/blob/main/LICENSE">
      <img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License">
    </a>
    <a href="https://docs.rs/fission-server">
      <img src="https://img.shields.io/static/v1?label=Docs&message=docs.rs&color=blue" alt="Docs">
    </a>
    <a href="https://fission.codes/discord">
      <img src="https://img.shields.io/static/v1?label=Discord&message=join%20us!&color=mediumslateblue" alt="Discord">
    </a>
  </p>
</div>

<div align="center"><sub>⚠️ Work in progress ⚠️</sub></div>


## Running the Webserver

### Using nix

```sh
nix run . -- --config-path ./fission-server/config/settings.toml
```

### Using pre-installed cargo & postgres

```sh
$ pg_ctl -o '-k /tmp' -D "./.pg" start
$ cargo run -p fission-server -- --config-path ./fission-server/config/settings.toml
```

## Development

You can drop into a development shell, if you have nix installed via

```sh
$ nix develop
```

from the project root.


You can re-build and re-run the webserver on every file change via `cargo watch`:

```sh
$ cargo watch -c -s "cargo run -p fission-server -- -c ./fission-server/config/settings.toml"
```

## Production

In production, you may want to enable the `--no-colors` flag on the executable.

All CLI flags are also available as environment-variables, so `FISSION_SERVER_NO_COLORS=true` and `FISSION_SERVER_CONFIG_PATH="./prod-settings.toml"` or even values from the `settings.toml` file itself.

You'll also want to set `server.environment = "prod"` in `settings.toml`, and with that you'll need to provide a valid `mailgun.api_key` (can also be set as the environment variable `FISSION_SERVER_MAILGUN_API_KEY=...`).
