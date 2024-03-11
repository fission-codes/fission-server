//! Top capability

use anyhow::{anyhow, Result};
use std::fmt::Display;

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
/// Top ability
pub enum Ability {
    /// *
    Top,
}

impl Display for Ability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Ability::Top => f.write_str("*"),
        }
    }
}

impl TryFrom<String> for Ability {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self> {
        Ok(match value.as_str() {
            "*" => Ability::Top,
            _ => return Err(anyhow!("Unrecognized ability: {:?}", value)),
        })
    }
}
