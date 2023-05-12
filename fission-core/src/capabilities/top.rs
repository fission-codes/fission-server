//! Top ability

use anyhow::{anyhow, Result};
use ucan::capability::Action;

/////////////
// ABILITY //
/////////////

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
pub enum Ability {
    Top,
}

impl Action for Ability {}

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
