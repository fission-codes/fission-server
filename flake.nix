{
  description = "fission-server";

  inputs = {
    nixpkgs.url = "nixpkgs/nixos-23.11";
    nixpkgs-unstable.url = "nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    command-utils.url = "github:expede/nix-command-utils";

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.flake-utils.follows = "flake-utils";
    };
  };

  outputs = {
    self,
    nixpkgs,
    nixpkgs-unstable,
    flake-utils,
    rust-overlay,
    command-utils,
  } @ inputs:
    flake-utils.lib.eachDefaultSystem (system: let
      overlays = [(import rust-overlay)];
      pkgs = import nixpkgs {inherit system overlays;};
      unstable = import nixpkgs-unstable {inherit system overlays;};

      rust-toolchain =
        pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;

      rustPlatform = pkgs.makeRustPlatform {
        cargo = rust-toolchain;
        rustc = rust-toolchain;
      };

      nightly-rustfmt = pkgs.rust-bin.nightly.latest.rustfmt;

      format-pkgs = with pkgs; [nixpkgs-fmt alejandra];

      cargo-installs = with pkgs;
        [
          cargo-deny
          cargo-expand
          cargo-outdated
          cargo-sort
          cargo-udeps
          cargo-watch
          diesel-cli
        ]
        ++ [unstable.cargo-dist];

      pgctl = "${pkgs.postgresql}/bin/pg_ctl";
      ipfs = "${pkgs.kubo}/bin/ipfs";
      cargo = "${pkgs.cargo}/bin/cargo";

      cmd = command-utils.cmd.${system};

      command_menu = command-utils.commands.${system} {
        db-start =
          cmd "Start the postgres database"
          ''${pgctl} -o "-k /tmp" -D "./.pg" -l postgres.log start'';

        db-stop =
          cmd "Stop the postgres database"
          ''${pgctl} -o "-k /tmp" -D "./.pg" stop'';

        ipfs-daemon =
          cmd "Start the IPFS (kubo) daemon"
          "${ipfs} --repo-dir ./.ipfs --offline daemon --init";

        server-watch =
          cmd
          "Rerun the server on every code change (Tip: use the RUST_LOG env variable)"
          "${cargo} watch -p fission-server -c -s '${cargo} run'";
      };
    in rec {
      devShells.default = pkgs.mkShell {
        name = "fission-server";
        nativeBuildInputs = with pkgs;
          [
            # The ordering of these two items is important. For nightly rustfmt to be used instead of
            # the rustfmt provided by `rust-toolchain`, it must appear first in the list. This is
            # because native build inputs are added to $PATH in the order they're listed here.
            nightly-rustfmt
            rust-toolchain
            pre-commit
            protobuf
            postgresql
            pgcli
            direnv
            kubo
            command_menu
          ]
          ++ format-pkgs
          ++ cargo-installs
          ++ lib.optionals stdenv.isDarwin [
            darwin.apple_sdk.frameworks.Security
            darwin.apple_sdk.frameworks.CoreFoundation
            darwin.apple_sdk.frameworks.Foundation
          ];

        shellHook = ''
          [ -e .git/hooks/pre-commit ] || pre-commit install

          PGDATA="./.pg";
          PGURL=postgres://postgres@localhost:5432/fission-server

          # Setup env variables for easier diesel CLI usage:
          export DATABASE_URL="$PGURL"

          # Initialize a local database if necessary.
          if [ ! -e $PGDATA ]; then
            echo -e "\nInitializing PostgreSQL in $PGDATA\n"
            initdb $PGDATA --no-instructions -A trust -U postgres
            if pg_ctl -o '-k /tmp' -D $PGDATA start; then
              cd fission-server
              diesel database setup
              cd ..
              pg_ctl -o '-k /tmp' -D $PGDATA stop
            else
              echo "Unable to start PostgreSQL server on default port (:5432). Maybe a local database is already running?"
            fi
          fi

          if [ ! -e $PGDATA/postmaster.pid ]; then
            echo -e "\nPostgreSQL not running."
            echo
          else
            echo -e "\nPostgreSQL is running."

            echo -e "\nRunning pending Diesel Migrations..."
            cd fission-server
            diesel migration run
            cd ..
            echo
          fi

          menu
        '';
      };

      formatter = pkgs.alejandra;

      packages.default = rustPlatform.buildRustPackage {
        name = "fission-server";
        src = ./.;
        cargoLock = {
          lockFile = ./Cargo.lock;
          outputHashes = {
            "rexpect-0.5.0" = "sha256-njjXt4pbLV3Z/ZkBzmBxcwDSqpbOttIpdg+kHND1vSo=";
            "rs-ucan-0.1.0" = "sha256-HSxIzqPECJ9KbPYU0aitjxpCf0CSDAv7su1PGxZlpHc=";
          };
        };
        buildInputs = with pkgs;
          [openssl postgresql rust-toolchain]
          ++ lib.optionals stdenv.isDarwin [
            darwin.apple_sdk.frameworks.Security
            darwin.apple_sdk.frameworks.CoreFoundation
            darwin.apple_sdk.frameworks.Foundation
          ];

        doCheck = false;

        OPENSSL_NO_VENDOR =
          1; # see https://github.com/sfackler/rust-openssl/pull/2122
      };
    });
}
