//! Fission account capabilities

use super::did::Did;
use anyhow::Result;
use rs_ucan::{
    plugins::Plugin,
    semantics::{ability::Ability, caveat::EmptyCaveat},
};
use std::fmt::Display;

/// An rs-ucan plugin for handling fission server capabilities
#[derive(Debug)]
pub struct FissionPlugin;

rs_ucan::register_plugin!(FISSION, &FissionPlugin);

/// Abilities for fission accounts
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FissionAbility {
    /// `account/read`, the ability to read account details like email address/username, etc.
    AccountRead,
    /// `account/create`, the ability to create an account
    AccountCreate,
    /// `account/manage`, the ability to change e.g. the username or email address
    AccountManage,
    /// `account/noncritical`, any non-destructive abilities like adding data or querying data
    AccountNonCritical,
    /// `account/delete`, the abilit to delete an account
    AccountDelete,
}

const ACCOUNT_READ: &str = "account/read";
const ACCOUNT_CREATE: &str = "account/create";
const ACCOUNT_MANAGE: &str = "account/manage";
const ACCOUNT_NON_CRITICAL: &str = "account/noncritical";
const ACCOUNT_DELETE: &str = "account/delete";

impl Plugin for FissionPlugin {
    type Resource = Did;
    type Ability = FissionAbility;
    type Caveat = EmptyCaveat;

    type Error = anyhow::Error;

    fn scheme(&self) -> &'static str {
        "did"
    }

    fn try_handle_resource(
        &self,
        resource_uri: &url::Url,
    ) -> Result<Option<Self::Resource>, Self::Error> {
        Ok(Did::try_handle_as_resource(resource_uri))
    }

    fn try_handle_ability(
        &self,
        _resource: &Self::Resource,
        ability: &str,
    ) -> Result<Option<Self::Ability>, Self::Error> {
        Ok(match ability {
            ACCOUNT_READ => Some(FissionAbility::AccountRead),
            ACCOUNT_CREATE => Some(FissionAbility::AccountCreate),
            ACCOUNT_MANAGE => Some(FissionAbility::AccountManage),
            ACCOUNT_NON_CRITICAL => Some(FissionAbility::AccountNonCritical),
            ACCOUNT_DELETE => Some(FissionAbility::AccountDelete),
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

impl Ability for FissionAbility {
    fn is_valid_attenuation(&self, other: &dyn Ability) -> bool {
        let Some(other) = other.downcast_ref::<Self>() else {
            return false;
        };

        if matches!(other, Self::AccountNonCritical) {
            return match self {
                Self::AccountRead => true,
                Self::AccountCreate => true,
                Self::AccountManage => false,
                Self::AccountNonCritical => true,
                Self::AccountDelete => false,
            };
        }

        self == other
    }
}

impl Display for FissionAbility {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::AccountRead => ACCOUNT_READ,
            Self::AccountCreate => ACCOUNT_CREATE,
            Self::AccountManage => ACCOUNT_MANAGE,
            Self::AccountNonCritical => ACCOUNT_NON_CRITICAL,
            Self::AccountDelete => ACCOUNT_DELETE,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ed_did_key::EdDidKey;
    use libipld::{raw::RawCodec, Ipld};
    use rs_ucan::{
        builder::UcanBuilder,
        capability::{Capability, DefaultCapabilityParser},
        did_verifier::DidVerifierMap,
        plugins::ucan::UcanResource,
        semantics::{ability::TopAbility, caveat::EmptyCaveat},
        store::{InMemoryStore, Store},
        time,
        ucan::Ucan,
        DefaultFact,
    };

    #[test]
    fn test_resource_can_be_delegated() -> Result<()> {
        let mut store = InMemoryStore::<RawCodec>::default();
        let did_verifier_map = DidVerifierMap::default();

        let alice = &EdDidKey::generate();
        let bob = &EdDidKey::generate();

        let root_ucan: Ucan<DefaultFact, DefaultCapabilityParser> = UcanBuilder::default()
            .for_audience(bob)
            .claiming_capability(Capability::new(
                UcanResource::AllProvable,
                TopAbility,
                EmptyCaveat {},
            ))
            .with_lifetime(60 * 60)
            .sign(alice)?;

        store.write(Ipld::Bytes(root_ucan.encode()?.as_bytes().to_vec()), None)?;

        let invocation: Ucan<DefaultFact, DefaultCapabilityParser> = UcanBuilder::default()
            .for_audience("did:web:fission.codes")
            .claiming_capability(Capability::new(
                Did("did:key:sth".to_string()),
                FissionAbility::AccountRead,
                EmptyCaveat {},
            ))
            .witnessed_by(&root_ucan, None)
            .with_lifetime(60 * 60)
            .sign(bob)?;

        let time = time::now();

        let capabilities = invocation.capabilities_for(
            alice.did(),
            Did("did:key:sth".to_string()),
            FissionAbility::AccountRead,
            time,
            &did_verifier_map,
            &store,
        )?;

        assert_eq!(capabilities.len(), 1);

        Ok(())
    }
}
