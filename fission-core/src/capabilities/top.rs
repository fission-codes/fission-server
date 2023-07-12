//! Top capability

use anyhow::{anyhow, Result};
use ucan::capability::Ability as UcanAbility;

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
/// Top ability
pub enum Ability {
    /// *
    Top,
}

impl UcanAbility for Ability {}

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
