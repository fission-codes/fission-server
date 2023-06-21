{
  description = "fission-server";

  inputs = {
    nixpkgs.url = "nixpkgs/nixos-22.11";
    flake-utils.url = "github:numtide/flake-utils";

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.flake-utils.follows = "flake-utils";
    };
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
    rust-overlay,
  } @ inputs:
    flake-utils.lib.eachDefaultSystem (
      system: let
        overlays = [(import rust-overlay)];
        pkgs = import nixpkgs {inherit system overlays;};

        rust-toolchain = (pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml).override {
          extensions = ["cargo" "clippy" "rustfmt" "rust-src" "rust-std"];
        };

        nightly-rustfmt = pkgs.rust-bin.nightly.latest.rustfmt;

        format-pkgs = with pkgs; [
          nixpkgs-fmt
          alejandra
        ];

        cargo-installs = with pkgs; [
          cargo-deny
          cargo-expand
          cargo-outdated
          cargo-sort
          cargo-udeps
          cargo-watch
          diesel-cli
        ];
      in rec
      {
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
              direnv
              self.packages.${system}.irust
            ]
            ++ format-pkgs
            ++ cargo-installs
            ++ lib.optionals stdenv.isDarwin [
              darwin.apple_sdk.frameworks.Security
              darwin.apple_sdk.frameworks.CoreFoundation
              darwin.apple_sdk.frameworks.Foundation
            ];

          shellHook = ''
            [ -e .git/hooks/pre-commit ] || pre-commit install --install-hooks && pre-commit install --hook-type commit-msg

            PGDATA="./.pg";

            # Initialize a local database if necessary.
            if [ ! -e $PGDATA ]; then
              echo -e "\nInitializing PostgreSQL in $PGDATA\n"
              initdb $PGDATA --no-instructions -A trust
              if pg_ctl -D $PGDATA start; then
                cd fission-server
                diesel database setup --database-url postgres://localhost:5432/fission-server
                cd ..
                pg_ctl -D $PGDATA stop
              else
                echo "Unable to start PostgreSQL server on default port (:5432). Maybe a local database is already running?"
              fi
            fi

            # Give instructions on how to start postgresql if it's not already running.
            if [ ! -e $PGDATA/postmaster.pid ]; then
              echo -e "\nPostgreSQL not running. To start, use the following command:"
              echo -e "  pg_ctl -D $PGDATA -l postgres.log start\n\n"
            else
              echo -e "\nPostgreSQL is running. To stop, use the following command:"
              echo -e "  pg_ctl -D $PGDATA stop\n\n"

              echo -e "\nRunning pending Diesel Migrations..."
              cd fission-server
              diesel migration run --database-url postgres://localhost:5432/fission-server
              cd ..
              echo
            fi
          '';
        };

        packages.irust = pkgs.rustPlatform.buildRustPackage rec {
          pname = "irust";
          version = "1.65.1";
          src = pkgs.fetchFromGitHub {
            owner = "sigmaSd";
            repo = "IRust";
            rev = "v${version}";
            sha256 = "sha256-AMOND5q1XzNhN5smVJp+2sGl/OqbxkGPGuPBCE48Hik=";
          };

          doCheck = false;
          cargoSha256 = "sha256-A24O3p85mCRVZfDyyjQcQosj/4COGNnqiQK2a7nCP6I=";
        };
      }
    );
}
