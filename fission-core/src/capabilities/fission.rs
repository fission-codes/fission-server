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
    /// `account/info`, the ability to read account information like email address/username, etc.
    AccountInfo,
    /// `account/create`, the ability to create an account
    AccountCreate,
    /// `account/link`, the ability to link the originator to an existing account via email challenge
    AccountLink,
    /// `account/manage`, the ability to change e.g. the username or email address
    AccountManage,
    /// `account/noncritical`, any non-destructive abilities like adding data or querying data
    AccountNonCritical,
    /// `account/delete`, the abilit to delete an account
    AccountDelete,
}

const ACCOUNT_READ: &str = "account/info";
const ACCOUNT_CREATE: &str = "account/create";
const ACCOUNT_LINK: &str = "account/link";
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
            ACCOUNT_READ => Some(FissionAbility::AccountInfo),
            ACCOUNT_CREATE => Some(FissionAbility::AccountCreate),
            ACCOUNT_LINK => Some(FissionAbility::AccountLink),
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
                Self::AccountInfo => true,
                Self::AccountCreate => true,
                Self::AccountLink => true,
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
            Self::AccountInfo => ACCOUNT_READ,
            Self::AccountCreate => ACCOUNT_CREATE,
            Self::AccountLink => ACCOUNT_LINK,
            Self::AccountManage => ACCOUNT_MANAGE,
            Self::AccountNonCritical => ACCOUNT_NON_CRITICAL,
            Self::AccountDelete => ACCOUNT_DELETE,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::ed_did_key::EdDidKey;
    use assert_matches::assert_matches;
    use libipld::{raw::RawCodec, Ipld};
    use rs_ucan::{
        builder::UcanBuilder,
        capability::{Capability, DefaultCapabilityParser},
        did_verifier::DidVerifierMap,
        plugins::ucan::UcanResource,
        semantics::{ability::TopAbility, caveat::EmptyCaveat},
        store::{InMemoryStore, Store},
        time::{self, now},
        ucan::Ucan,
        DefaultFact,
    };
    use testresult::TestResult;

    #[test_log::test]
    fn test_resource_can_be_delegated() -> TestResult {
        let mut store = InMemoryStore::<RawCodec>::default();
        let did_verifier_map = DidVerifierMap::default();

        let alice = &EdDidKey::generate();
        let bob = &EdDidKey::generate();

        let root_ucan: Ucan<DefaultFact, DefaultCapabilityParser> = UcanBuilder::default()
            .for_audience(bob)
            .claiming_capability(Capability::new(
                UcanResource::AllProvable,
                TopAbility,
                EmptyCaveat,
            ))
            .with_lifetime(60 * 60)
            .sign(alice)?;

        store.write(Ipld::Bytes(root_ucan.encode()?.as_bytes().to_vec()), None)?;

        let invocation: Ucan<DefaultFact, DefaultCapabilityParser> = UcanBuilder::default()
            .for_audience("did:web:fission.codes")
            .claiming_capability(Capability::new(
                Did("did:key:sth".to_string()),
                FissionAbility::AccountInfo,
                EmptyCaveat,
            ))
            .witnessed_by(&root_ucan, None)
            .with_lifetime(60 * 60)
            .sign(bob)?;

        let time = time::now();

        let capabilities = invocation.capabilities_for(
            alice.did(),
            Did("did:key:sth".to_string()),
            FissionAbility::AccountInfo,
            time,
            &did_verifier_map,
            &store,
        )?;

        assert_eq!(capabilities.len(), 1);

        Ok(())
    }

    #[ignore = "waiting for rs_ucan updates to support ucan:<did> scheme"]
    #[test]
    fn test_broken_ucan() -> Result<()> {
        let issuer = &EdDidKey::generate();
        let ucan: Ucan = UcanBuilder::default()
            .for_audience(issuer)
            .claiming_capability(Capability::new(
                UcanResource::OwnedBy(issuer.did()),
                TopAbility,
                EmptyCaveat,
            ))
            .sign(issuer)?;

        // This should work
        assert_matches!(
            Ucan::<DefaultFact, DefaultCapabilityParser>::from_str(&ucan.encode()?),
            Ok(_)
        );

        Ok(())
    }

    #[test_log::test]
    #[ignore]
    fn test_powerbox_ucan_resource() -> TestResult {
        let store = InMemoryStore::<RawCodec>::default();
        let did_verifier_map = DidVerifierMap::default();

        let server = &EdDidKey::generate();
        let device = &EdDidKey::generate();

        // Both of these UCANs just create ephemeral DIDs & delegate all of those
        // DID's rights to the server
        let (account_did, account_ucan) = server_create_resource(server)?;
        let (dnslink_did, dnslink_ucan) = server_create_resource(server)?;

        // This UCAN gives account access to the device
        let device_ucan: Ucan = UcanBuilder::default()
            .for_audience(device)
            .claiming_capability(Capability::new(
                UcanResource::AllProvable, // UcanResource::OwnedBy(account_did.to_string()),
                TopAbility,
                EmptyCaveat,
            ))
            .witnessed_by(&account_ucan, None)
            .sign(server)?;

        // This UCAN assigns access to the DNSLink to anyone who has access to the account
        let account_assoc_ucan: Ucan = UcanBuilder::default()
            .for_audience(&account_did)
            .claiming_capability(Capability::new(
                dnslink_did.clone(),
                TopAbility,
                EmptyCaveat,
            ))
            .witnessed_by(&dnslink_ucan, None)
            .sign(server)?;

        // The device should now be able to use the capability, because
        // - it's got access to the account
        // - the account got delegated rights to the DNSLink
        let invocation: Ucan = UcanBuilder::default()
            .for_audience(server)
            .claiming_capability(Capability::new(
                dnslink_did.clone(),
                FissionAbility::AccountInfo,
                EmptyCaveat,
            ))
            .witnessed_by(&device_ucan, None)
            .witnessed_by(&account_assoc_ucan, None)
            .sign(device)?;

        let caps = invocation.capabilities_for(
            &dnslink_did.clone(),
            dnslink_did,
            FissionAbility::AccountInfo,
            now(),
            &did_verifier_map,
            &store,
        )?;

        tracing::debug!(?caps, "Capabilities");

        assert!(!caps.is_empty());

        Ok(())
    }

    fn server_create_resource(server: &EdDidKey) -> Result<(Did, Ucan)> {
        let resource = &EdDidKey::generate();
        let did = Did(resource.did());

        let ucan = UcanBuilder::default()
            .for_audience(server)
            .claiming_capability(Capability::new(
                UcanResource::AllProvable, // UcanResource::OwnedBy(resource.did()),
                TopAbility,
                EmptyCaveat,
            ))
            .sign(server)?;

        Ok((did, ucan))
    }
}
