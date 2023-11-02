//! Capabilities for using the capability indexing endpoint

use super::did::Did;
use rs_ucan::{
    plugins::Plugin,
    semantics::{ability::Ability, caveat::EmptyCaveat},
};
use std::fmt::Display;

/// rs_ucan plugin for handling capability abilities
#[derive(Debug)]
pub struct IndexingPlugin;

rs_ucan::register_plugin!(INDEXING, &IndexingPlugin);

/// Abilities for the UCAN and capability indexing endpoints
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndexingAbility {
    /// `capability/fetch` ability
    Fetch,
}

const CAPABILITY_FETCH: &str = "capability/fetch";

impl Plugin for IndexingPlugin {
    type Resource = Did;
    type Ability = IndexingAbility;
    type Caveat = EmptyCaveat;

    type Error = anyhow::Error;

    fn scheme(&self) -> &'static str {
        "did"
    }

    fn try_handle_resource(
        &self,
        resource_uri: &url::Url,
    ) -> std::result::Result<Option<Self::Resource>, Self::Error> {
        Ok(Did::try_handle_as_resource(resource_uri))
    }

    fn try_handle_ability(
        &self,
        _resource: &Self::Resource,
        ability: &str,
    ) -> std::result::Result<Option<Self::Ability>, Self::Error> {
        Ok(match ability {
            CAPABILITY_FETCH => Some(IndexingAbility::Fetch),
            _ => None,
        })
    }

    fn try_handle_caveat(
        &self,
        _resource: &Self::Resource,
        _ability: &Self::Ability,
        deserializer: &mut dyn erased_serde::Deserializer<'_>,
    ) -> std::result::Result<Option<Self::Caveat>, Self::Error> {
        Ok(Some(
            erased_serde::deserialize(deserializer).map_err(|e| anyhow::anyhow!(e))?,
        ))
    }
}

impl Ability for IndexingAbility {
    fn is_valid_attenuation(&self, other: &dyn Ability) -> bool {
        let Some(other) = other.downcast_ref::<IndexingAbility>() else {
            return false;
        };

        self == other
    }
}

impl Display for IndexingAbility {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Fetch => CAPABILITY_FETCH,
        })
    }
}
