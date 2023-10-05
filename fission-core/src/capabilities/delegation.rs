//! Delegation capabilities

use anyhow::{anyhow, Result};
use ucan::capability::{Ability, CapabilitySemantics, Scope};
use url::Url;

//////////////
// RESOURCE //
//////////////

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
/// Fission resources
pub enum FissionResource {
    /// The volume associated with this account
    Volume,
}

impl Scope for FissionResource {
    fn contains(&self, _other: &Self) -> bool {
        true
    }
}

impl ToString for FissionResource {
    fn to_string(&self) -> String {
        match self {
            Self::Volume => "volume:/".to_string(),
        }
    }
}

impl TryFrom<Url> for FissionResource {
    type Error = anyhow::Error;

    fn try_from(resource: Url) -> Result<Self> {
        match resource.scheme() {
            "volume" => Ok(Self::Volume),
            _ => Err(anyhow!("Unrecognized resource: {resource}")),
        }
    }
}

/////////////
// ABILITY //
/////////////

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
/// Delegation ability
pub enum FissionAbility {
    /// Delegate any & all abilities
    Any,
    /// Ability to update a volume
    VolumeUpdate,
}

impl Ability for FissionAbility {}

impl ToString for FissionAbility {
    fn to_string(&self) -> String {
        match self {
            FissionAbility::Any => "*",
            FissionAbility::VolumeUpdate => "volume/update",
        }
        .to_string()
    }
}

impl TryFrom<String> for FissionAbility {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self> {
        if value == "*" {
            Ok(FissionAbility::Any)
        } else if value == "volume/update" {
            Ok(FissionAbility::VolumeUpdate)
        } else {
            Err(anyhow!("Couldn't parse ability \"{value}\""))
        }
    }
}

///////////////
// SEMANTICS //
///////////////

#[derive(Debug)]
/// Semantics
pub struct FissionSemantics;

impl CapabilitySemantics<FissionResource, FissionAbility> for FissionSemantics {}
