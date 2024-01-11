use anyhow::Result;
use config::{Config, ConfigError, Environment, File, Map, Source, Value, ValueKind};
use serde::{Deserialize, Serialize};
use std::{marker::PhantomData, path::PathBuf};
use url::Url;

use crate::paths::{config_file, default_key_file, http_cache_dir};

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

        let s = Config::builder()
            .add_source(DefaultImplSource::<Settings>::new())
            .add_source(File::with_name(&path.as_path().display().to_string()))
            .add_source(
                Environment::with_prefix("FISSION")
                    .separator("_")
                    .try_parsing(true),
            )
            .build()?;
        Ok(s.try_deserialize()?)
    }
}

// All of the below is kinda stupid.
// This is to support loading without a config, and having default values
// provided from the `Default` implementation of `Settings`.
// This works by serializing `Settings::default()` into `toml::Value`
// and then copying over the code that exists in `config` that takes
// a `toml::Value` and turns it into a `config::Value`.

struct DefaultImplSource<T: Default>(PhantomData<T>);

impl<T: Default> Clone for DefaultImplSource<T> {
    fn clone(&self) -> Self {
        Self::new()
    }
}

impl<T: Default> std::fmt::Debug for DefaultImplSource<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("DefaultImplSource").finish()
    }
}

impl<T: Default> DefaultImplSource<T> {
    pub fn new() -> Self {
        Self(PhantomData)
    }
}

impl<T: Default + Send + Sync + 'static> Source for DefaultImplSource<T> {
    fn clone_into_box(&self) -> Box<dyn Source + Send + Sync> {
        Box::new(self.clone())
    }

    fn collect(&self) -> Result<Map<String, Value>, ConfigError> {
        let def = Settings::default();
        let toml_value = toml::Value::try_from(def).unwrap();
        let value = from_toml_value(&toml_value);
        match value.kind {
            ValueKind::Table(map) => Ok(map),
            _ => Ok(Map::new()),
        }
    }
}

fn from_toml_value(value: &toml::Value) -> Value {
    match *value {
        toml::Value::String(ref value) => Value::new(None, value.to_string()),
        toml::Value::Float(value) => Value::new(None, value),
        toml::Value::Integer(value) => Value::new(None, value),
        toml::Value::Boolean(value) => Value::new(None, value),

        toml::Value::Table(ref table) => {
            let mut m = Map::new();

            for (key, value) in table {
                m.insert(key.clone(), from_toml_value(value));
            }

            Value::new(None, m)
        }

        toml::Value::Array(ref array) => {
            let mut l = Vec::new();

            for value in array {
                l.push(from_toml_value(value));
            }

            Value::new(None, l)
        }

        toml::Value::Datetime(ref datetime) => Value::new(None, datetime.to_string()),
    }
}
