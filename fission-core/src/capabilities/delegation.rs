//! Delegation capabilities

use anyhow::{anyhow, Result};
use ucan::capability::{Action, CapabilitySemantics, Scope};
use url::Url;

//////////////
// RESOURCE //
//////////////

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
/// Delegation resource
pub enum Resource {
    /// All possible provable UCANs
    AllProvableUCANs,

    /// All in this UCAN's proofs
    AllProofs,
}

impl Scope for Resource {
    fn contains(&self, other: &Self) -> bool {
        match self {
            Resource::AllProvableUCANs => match other {
                Resource::AllProvableUCANs => true,
                Resource::AllProofs => true,
            },

            Resource::AllProofs => match other {
                Resource::AllProvableUCANs => false,
                Resource::AllProofs => true,
            },
        }
    }
}

impl ToString for Resource {
    fn to_string(&self) -> String {
        match self {
            Resource::AllProvableUCANs => "ucan:*",
            Resource::AllProofs => "ucan:./*",
        }
        .into()
    }
}

impl TryFrom<Url> for Resource {
    type Error = anyhow::Error;

    fn try_from(value: Url) -> Result<Self> {
        println!("in here!! parsing resource! {:?}", value);
        match value.scheme() {
            "ucan" => match value.path() {
                "*" => Ok(Resource::AllProvableUCANs),
                "./*" => Ok(Resource::AllProofs),
                _ => Err(anyhow!(
                    "Could not interpret URI as a delegation resource: {:?}",
                    value
                )),
            },
            _ => Err(anyhow!(
                "Could not interpret URI as a delegation resource: {:?}",
                value
            )),
        }
    }
}

/////////////
// ABILITY //
/////////////

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
/// Delegation ability
pub enum Ability {
    /// Target all the capabilities
    AllCapabilities,
}

impl Action for Ability {}

impl ToString for Ability {
    fn to_string(&self) -> String {
        match self {
            Ability::AllCapabilities => "ucan/*",
        }
        .into()
    }
}

impl TryFrom<String> for Ability {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self> {
        println!("in here!! parsing ability! {}", value);
        Ok(match value.as_str() {
            "ucan/*" => Ability::AllCapabilities,
            _ => return Err(anyhow!("Unrecognized ability: {:?}", value)),
        })
    }
}

///////////////
// SEMANTICS //
///////////////

#[derive(Debug)]
/// Semantics
pub struct Semantics {}

impl CapabilitySemantics<Resource, Ability> for Semantics {}

/// Semantics constant
pub const SEMANTICS: Semantics = Semantics {};
