use anyhow::Result;
use clap::Parser;
use fission_cli::{cli::Cli, settings::Settings};
use tracing_subscriber::{prelude::*, util::SubscriberInitExt, EnvFilter};

fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .with(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    let settings = Settings::load()?;
    cli.run(settings)?;

    Ok(())
}
