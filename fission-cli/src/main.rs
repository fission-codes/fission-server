use anyhow::Result;
use clap::Parser;
use fission_cli::{cli::Cli, settings::Settings};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let settings = Settings::load()?;
    cli.run(settings).await?;

    Ok(())
}
