//! Email abilities

use std::fmt::Display;

use rs_ucan::{
    plugins::Plugin,
    semantics::{ability::Ability, caveat::EmptyCaveat},
};

use super::did::Did;

/// An rs-ucan plugin for email
#[derive(Debug)]
pub struct EmailPlugin;

rs_ucan::register_plugin!(EMAIL, &EmailPlugin);

/// Email Abilities
#[derive(Debug, Clone)]
pub enum EmailAbility {
    /// The ability to initiate email address verification
    Verify,
}

impl Ability for EmailAbility {
    fn is_valid_attenuation(&self, other: &dyn Ability) -> bool {
        match other.downcast_ref() {
            Some(EmailAbility::Verify) => true,
            None => false,
        }
    }
}

impl Display for EmailAbility {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("email/verify")
    }
}

impl Plugin for EmailPlugin {
    type Resource = Did;
    type Ability = EmailAbility;
    type Caveat = EmptyCaveat;
    type Error = anyhow::Error;

    fn scheme(&self) -> &'static str {
        "did"
    }

    fn try_handle_resource(
        &self,
        resource_uri: &url::Url,
    ) -> Result<Option<Self::Resource>, Self::Error> {
        Ok(Some(Did(resource_uri.to_string())))
    }

    fn try_handle_ability(
        &self,
        _resource: &Self::Resource,
        ability: &str,
    ) -> Result<Option<Self::Ability>, Self::Error> {
        Ok(match ability {
            "email/verify" => Some(EmailAbility::Verify),
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
