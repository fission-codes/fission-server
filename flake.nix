{
  description = "fission-server";

  inputs = {
    nixpkgs.url = "nixpkgs/nixos-23.11";
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
  }:
    flake-utils.lib.eachDefaultSystem (system: let
      overlays = [(import rust-overlay)];
      pkgs = import nixpkgs {inherit system overlays;};

      rust-toolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;

      rustPlatform = pkgs.makeRustPlatform {
        cargo = rust-toolchain;
        rustc = rust-toolchain;
      };

      nightly-rustfmt = pkgs.rust-bin.nightly.latest.rustfmt;

      format-pkgs = with pkgs; [nixpkgs-fmt alejandra];

      cargo-installs = with pkgs; [
        cargo-deny
        cargo-expand
        cargo-outdated
        cargo-sort
        cargo-udeps
        cargo-watch
        diesel-cli
      ];
    in {
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
            self.packages.${system}.irust
            kubo
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
          PGURL=postgres://postgres@localhost:5432/fission-server

          # Initialize a local database if necessary.
          if [ ! -e $PGDATA ]; then
            echo -e "\nInitializing PostgreSQL in $PGDATA\n"
            initdb $PGDATA --no-instructions -A trust -U postgres
            if pg_ctl -o '-k /tmp' -D $PGDATA start; then
              cd fission-server
              diesel database setup --database-url $PGURL
              cd ..
              pg_ctl -o '-k /tmp' -D $PGDATA stop
            else
              echo "Unable to start PostgreSQL server on default port (:5432). Maybe a local database is already running?"
            fi
          fi

          # Give instructions on how to start postgresql if it's not already running.
          if [ ! -e $PGDATA/postmaster.pid ]; then
            echo -e "\nPostgreSQL not running. To start, use the following command:"
            echo -e "  pg_ctl -o '-k /tmp' -D $PGDATA -l postgres.log start\n\n"
          else
            echo -e "\nPostgreSQL is running. To stop, use the following command:"
            echo -e "  pg_ctl -o '-k /tmp' -D $PGDATA stop\n\n"

            echo -e "\nRunning pending Diesel Migrations..."
            cd fission-server
            diesel migration run --database-url $PGURL
            cd ..
            echo
          fi

          # Setup local Kubo config
          if [ ! -e ./.ipfs ]; then
            ipfs --repo-dir ./.ipfs --offline init
          fi

          # Run Kubo
          echo -e "To run Kubo as a local IPFS node, use the following command:"
          echo -e " ipfs --repo-dir ./.ipfs --offline daemon"
          echo

          # Setup env variables for easier diesel CLI usage:
          export DATABASE_URL="$PGURL"
        '';
      };

      formatter = pkgs.alejandra;

      packages.irust = rustPlatform.buildRustPackage rec {
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

        nativeBuildInputs = with pkgs; [pkg-config];

        OPENSSL_NO_VENDOR = 1; # see https://github.com/sfackler/rust-openssl/pull/2122
      };
    });
}
