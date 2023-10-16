//! Fission account capabilities

use std::fmt::Display;

use anyhow::Result;
use rs_ucan::{
    plugins::{ucan::UcanResource, Plugin},
    semantics::{ability::Ability, caveat::EmptyCaveat, resource::Resource},
};

/// An rs-ucan plugin for handling fission server capabilities
#[derive(Debug)]
pub struct FissionPlugin;

rs_ucan::register_plugin!(FISSION, &FissionPlugin);

/// Resources supported by the fission server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FissionResource {
    /// The resource encoded as `fission:*`, giving access to all current or future owned accounts
    All,
    /// The resource encoded as `fission:did:key:zABC` for a specific fission account
    Did(String),
}

/// Abilities for fission accounts
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FissionAbility {
    /// `account/read`, the ability to read account details like email address/username, etc.
    AccountRead,
    /// `account/create`, the ability to create an account
    AccountCreate,
}

impl Plugin for FissionPlugin {
    type Resource = FissionResource;
    type Ability = FissionAbility;
    type Caveat = EmptyCaveat;

    type Error = anyhow::Error;

    fn scheme(&self) -> &'static str {
        "fission"
    }

    fn try_handle_resource(
        &self,
        resource_uri: &url::Url,
    ) -> Result<Option<Self::Resource>, Self::Error> {
        let path = resource_uri.path();

        if path == "*" {
            return Ok(Some(FissionResource::All));
        }

        if !path.starts_with("did:key:") {
            return Ok(None);
        }

        Ok(Some(FissionResource::Did(path.to_string())))
    }

    fn try_handle_ability(
        &self,
        _resource: &Self::Resource,
        ability: &str,
    ) -> Result<Option<Self::Ability>, Self::Error> {
        Ok(match ability {
            "account/read" => Some(FissionAbility::AccountRead),
            "account/create" => Some(FissionAbility::AccountCreate),
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

impl Resource for FissionResource {
    fn is_valid_attenuation(&self, other: &dyn Resource) -> bool {
        if let Some(UcanResource::AllProvable) = other.downcast_ref() {
            return true;
        }

        match other.downcast_ref() {
            Some(Self::All) => true,
            Some(Self::Did(did)) => match self {
                Self::All => false,
                Self::Did(self_did) => self_did == did,
            },
            _ => false,
        }
    }
}

impl Display for FissionResource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("fission:")?;
        f.write_str(match self {
            Self::All => "*",
            Self::Did(did) => did,
        })
    }
}

impl Ability for FissionAbility {
    fn is_valid_attenuation(&self, other: &dyn Ability) -> bool {
        let Some(other) = other.downcast_ref::<FissionAbility>() else {
            return false;
        };

        self == other
    }
}

impl Display for FissionAbility {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::AccountRead => "account/read",
            Self::AccountCreate => "account/create",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ed_did_key::EdDidKey;
    use libipld::{raw::RawCodec, Ipld};
    use rs_ucan::{
        builder::{UcanBuilder, DEFAULT_MULTIHASH},
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
            .issued_by(alice)
            .for_audience(bob)
            .claiming_capability(Capability::new(
                UcanResource::AllProvable,
                TopAbility,
                EmptyCaveat {},
            ))
            .with_lifetime(60 * 60)
            .sign(alice)?;

        store.write(
            Ipld::Bytes(root_ucan.encode()?.as_bytes().to_vec()),
            DEFAULT_MULTIHASH,
        )?;

        let invocation: Ucan<DefaultFact, DefaultCapabilityParser> = UcanBuilder::default()
            .issued_by(bob)
            .for_audience("did:web:fission.codes")
            .claiming_capability(Capability::new(
                FissionResource::Did("did:key:sth".to_string()),
                FissionAbility::AccountRead,
                EmptyCaveat {},
            ))
            .witnessed_by(&root_ucan, None)
            .with_lifetime(60 * 60)
            .sign(bob)?;

        let time = time::now();

        let capabilities = invocation.capabilities_for(
            alice.did(),
            FissionResource::Did("did:key:sth".to_string()),
            FissionAbility::AccountRead,
            time,
            &did_verifier_map,
            &store,
        )?;

        assert_eq!(capabilities.len(), 1);

        Ok(())
    }
}
