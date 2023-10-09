//! Top capability

use anyhow::{anyhow, Result};

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
/// Top ability
pub enum Ability {
    /// *
    Top,
}

impl ToString for Ability {
    fn to_string(&self) -> String {
        match self {
            Ability::Top => "*",
        }
        .into()
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
