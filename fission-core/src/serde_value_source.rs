//! This module is kinda stupid.
//! This is to support loading values into a config from some existing defaults.
//! This works by serializing the value inside `SerdeValueSource` into `toml::Value`
//! and then copying over the code that exists in `config` that takes
//! a `toml::Value` and turns it into a `config::Value`.
use anyhow::Result;
use config::{ConfigError, Map, Source, Value, ValueKind};
use serde::Serialize;
use std::fmt::Debug;

/// Load a serde-serializable value into a config from the config crate.
#[derive(Clone, Debug)]
pub struct SerdeValueSource<T: Serialize>(T);

impl<T: Serialize> From<T> for SerdeValueSource<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}

impl<T: Serialize + Debug + Clone + Send + Sync + 'static> Source for SerdeValueSource<T> {
    fn clone_into_box(&self) -> Box<dyn Source + Send + Sync> {
        Box::new(self.clone())
    }

    fn collect(&self) -> Result<Map<String, Value>, ConfigError> {
        let toml_value =
            toml::Value::try_from(&self.0).map_err(|e| ConfigError::Message(e.to_string()))?;
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
