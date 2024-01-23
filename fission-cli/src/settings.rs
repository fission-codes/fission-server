use crate::paths::{config_file, default_key_file, http_cache_dir};
use anyhow::Result;
use config::{Config, Environment, File};
use fission_core::serde_value_source::SerdeValueSource;
use serde::{Deserialize, Serialize};
use std::{fmt::Debug, path::PathBuf};
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    /// The path of where the main private key .pem file is supposed to be stored
    pub key_file: PathBuf,
    /// server address
    pub api_endpoint: Url,
    /// where to store the http cache
    pub http_cache_dir: PathBuf,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            key_file: default_key_file(),
            api_endpoint: Url::parse("http://localhost:3000").expect("Valid hardcoded server URL"), // TODO update this once the server is deployed somewhere
            http_cache_dir: http_cache_dir(),
        }
    }
}

impl Settings {
    pub fn load() -> Result<Self> {
        let path = config_file();

        let mut builder = Config::builder().add_source(SerdeValueSource::from(Settings::default()));

        if path.exists() {
            builder = builder.add_source(File::with_name(&path.as_path().display().to_string()));
        }

        builder = builder.add_source(
            Environment::with_prefix("FISSION")
                .separator("_")
                .try_parsing(true),
        );

        let s = builder.build()?;

        Ok(s.try_deserialize()?)
    }
}
