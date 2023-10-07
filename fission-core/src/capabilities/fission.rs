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

/// Resources supported by the fission server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FissionResource {
    /// The `fission:did:key:zABC` resource for fission accounts
    pub(crate) did: String,
}

/// Abilities for fission accounts
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FissionAbility {
    /// `account/read`, the ability to read account details like email address/username, etc.
    AccountRead,
}

rs_ucan::register_plugin!(FISSION, &FissionPlugin);

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
        let did = resource_uri.path();

        if !did.starts_with("did:key:") {
            return Ok(None);
        }

        Ok(Some(FissionResource {
            did: did.to_string(),
        }))
    }

    fn try_handle_ability(
        &self,
        _resource: &Self::Resource,
        ability: &str,
    ) -> Result<Option<Self::Ability>, Self::Error> {
        Ok(match ability {
            "account/read" => Some(FissionAbility::AccountRead),
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

        let Some(FissionResource { did }) = other.downcast_ref() else {
            return false;
        };

        &self.did == did
    }
}

impl Display for FissionResource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("fission:")?;
        f.write_str(&self.did)
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
        match self {
            Self::AccountRead => f.write_str("account/read"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use did_key::{Ed25519KeyPair, Fingerprint};
    use ed25519_dalek::VerifyingKey;
    use libipld::{raw::RawCodec, Ipld};
    use rand::thread_rng;
    use rs_ucan::{
        builder::{UcanBuilder, DEFAULT_MULTIHASH},
        capability::{Capability, DefaultCapabilityParser},
        crypto::eddsa::ed25519_dalek_verifier,
        did_verifier::{did_key::DidKeyVerifier, DidVerifierMap},
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
        let mut did_key_verifier = DidKeyVerifier::default();
        did_key_verifier.set::<ed25519::Signature, _>(ed25519_dalek_verifier);

        let mut did_verifier_map = DidVerifierMap::default();
        did_verifier_map.register(did_key_verifier);

        let alice = ed25519_dalek::SigningKey::generate(&mut thread_rng());
        let bob = ed25519_dalek::SigningKey::generate(&mut thread_rng());

        let root_ucan: Ucan<DefaultFact, DefaultCapabilityParser> = UcanBuilder::default()
            .issued_by(did_key_str(alice.verifying_key()))
            .for_audience(did_key_str(bob.verifying_key()))
            .claiming_capability(Capability {
                resource: Box::new(UcanResource::AllProvable),
                ability: Box::new(TopAbility),
                caveat: Box::new(EmptyCaveat {}),
            })
            .with_lifetime(60 * 60)
            .sign(&alice)?;

        store.write(
            Ipld::Bytes(root_ucan.encode()?.as_bytes().to_vec()),
            DEFAULT_MULTIHASH,
        )?;

        let invocation: Ucan<DefaultFact, DefaultCapabilityParser> = UcanBuilder::default()
            .issued_by(did_key_str(bob.verifying_key()))
            .for_audience("did:web:fission.codes")
            .claiming_capability(Capability {
                resource: Box::new(FissionResource {
                    did: "did:key:sth".to_string(),
                }),
                ability: Box::new(FissionAbility::AccountRead),
                caveat: Box::new(EmptyCaveat {}),
            })
            .witnessed_by(&root_ucan, None)
            .with_lifetime(60 * 60)
            .sign(&bob)?;

        let time = time::now();

        let capabilities = invocation.capabilities_for(
            did_key_str(alice.verifying_key()),
            FissionResource {
                did: "did:key:sth".to_string(),
            },
            FissionAbility::AccountRead,
            time,
            &did_verifier_map,
            &store,
        )?;

        assert_eq!(capabilities.len(), 1);

        Ok(())
    }

    fn did_key_str(key: VerifyingKey) -> String {
        format!(
            "did:key:{}",
            Ed25519KeyPair::from_public_key(key.as_bytes()).fingerprint()
        )
    }
}
