//! Volume capabilities

use std::fmt::Display;

use rs_ucan::{
    plugins::{ucan::UcanResource, Plugin},
    semantics::{ability::Ability, caveat::EmptyCaveat, resource::Resource},
};

/// An rs-ucan plugin for volume capabilities
#[derive(Debug)]
pub struct VolumePlugin;

/// The volume resource supported by the fission server
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeResource {
    did: String,
}

/// Actions/Abilities supported on volumes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VolumeAbility {
    /// The ability to update the volume CID
    Update,
}

rs_ucan::register_plugin!(VOLUME, &VolumePlugin);

impl Plugin for VolumePlugin {
    type Resource = VolumeResource;
    type Ability = VolumeAbility;
    type Caveat = EmptyCaveat;
    type Error = anyhow::Error;

    fn scheme(&self) -> &'static str {
        "volume"
    }

    fn try_handle_resource(
        &self,
        resource_uri: &url::Url,
    ) -> Result<Option<Self::Resource>, Self::Error> {
        let did = resource_uri.path();

        if !did.starts_with("did:key:") {
            return Ok(None);
        }

        Ok(Some(VolumeResource {
            did: did.to_string(),
        }))
    }

    fn try_handle_ability(
        &self,
        _resource: &Self::Resource,
        ability: &str,
    ) -> Result<Option<Self::Ability>, Self::Error> {
        Ok(match ability {
            "volume/update" => Some(VolumeAbility::Update),
            _ => None,
        })
    }

    fn try_handle_caveat(
        &self,
        _resource: &Self::Resource,
        _ability: &Self::Ability,
        deserializer: &mut dyn erased_serde::Deserializer<'_>,
    ) -> Result<Option<Self::Caveat>, Self::Error> {
        Ok(Some(
            erased_serde::deserialize(deserializer).map_err(|e| anyhow::anyhow!(e))?,
        ))
    }
}

impl Resource for VolumeResource {
    fn is_valid_attenuation(&self, other: &dyn Resource) -> bool {
        if let Some(UcanResource::AllProvable) = other.downcast_ref() {
            return true;
        }

        let Some(VolumeResource { did }) = other.downcast_ref() else {
            return false;
        };

        &self.did == did
    }
}

impl Display for VolumeResource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("volume:")?;
        f.write_str(&self.did)
    }
}

impl Ability for VolumeAbility {
    fn is_valid_attenuation(&self, other: &dyn Ability) -> bool {
        let Some(other) = other.downcast_ref::<VolumeAbility>() else {
            return false;
        };

        self == other
    }
}

impl Display for VolumeAbility {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Update => f.write_str("volume/update"),
        }
    }
}
