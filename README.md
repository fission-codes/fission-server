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

To start-up the fission server, run:

```console
APP__MAILGUN__API_KEY=::ask-blaine:: cargo watch -c -s "cargo run --features ansi-logs"
```
