//! Authority struct and functions

use anyhow::{anyhow, bail, Result};
use fission_core::capabilities::did::Did;
use libipld::{raw::RawCodec, Ipld};
use rs_ucan::{
    did_verifier::DidVerifierMap,
    semantics::ability::Ability,
    store::{InMemoryStore, Store},
    ucan::Ucan,
    DefaultFact,
};
use serde::de::DeserializeOwned;

//-------//
// TYPES //
//-------//

#[derive(Debug, Clone)]
/// Represents the authority of an incoming request
pub struct Authority<F = DefaultFact> {
    /// https://github.com/ucan-wg/ucan-as-bearer-token#21-entry-point
    pub ucan: Ucan<F>,
    /// proofs from `ucan` header
    pub proofs: Vec<Ucan>,
}

//-----------------//
// IMPLEMENTATIONS //
//-----------------//

impl<F: Clone + DeserializeOwned> Authority<F> {
    /// Validate an authority struct
    pub fn validate(&self, server_did: &str) -> Result<()> {
        self.ucan
            .validate(rs_ucan::time::now(), &DidVerifierMap::default())?;

        let audience = self.ucan.audience();
        if audience != server_did {
            tracing::error!(
                audience = %audience,
                expected = %server_did,
                token = ?self.ucan.encode(),
                "Auth token audience doesn't match server DID"
            );
            bail!("Auth token audience doesn't match server DID. Expected {server_did}, but got {audience}.")
        }

        Ok(())
    }

    /// Validates whether or not the UCAN and proofs have the capability to
    /// perform the given action, with the given issuer as the root of that
    /// authority.
    pub fn get_capability(&self, ability: impl Ability) -> Result<Did> {
        let current_time = rs_ucan::time::now();

        let mut store = InMemoryStore::<RawCodec>::default();

        for proof in &self.proofs {
            // TODO(matheus23): we assume SHA2-256 atm. The spec says to hash with all CID formats used in proofs >.<
            store.write(Ipld::Bytes(proof.encode()?.as_bytes().to_vec()), None)?;
        }

        let caps = self.ucan.capabilities().collect::<Vec<_>>();
        let [cap] = caps[..] else {
            if caps.is_empty() {
                tracing::error!("No capabilities provided.");
                bail!("Invocation UCAN without capabilities provided.");
            }
            tracing::error!(caps = ?caps, "Invocation UCAN with multiple capabilities is ambiguous.");
            bail!("Invocation UCAN with multiple capabilities is ambiguous.");
        };

        if !cap.ability().is_valid_attenuation(&ability) {
            bail!(
                "Invalid authorization. Expected ability {ability}, but got {}",
                cap.ability()
            );
        }

        let Some(Did(did)) = cap.resource().downcast_ref() else {
            bail!(
                "Invalid authorization. Expected resource to be DID, but got {}",
                cap.resource()
            );
        };

        let ability_str = ability.to_string();

        let caps = self.ucan.capabilities_for(
            did,
            Did(did.clone()),
            ability,
            current_time,
            &DidVerifierMap::default(),
            &store,
        )?;

        // TODO(matheus23): Not yet handling caveats.
        caps.first()
            .ok_or_else(|| {
                anyhow!(
                    "Invalid authorization. Couldn't find proof for {ability_str} as issued from {did}"
                )
            })?
            .resource()
            .downcast_ref()
            .cloned()
            .ok_or_else(|| anyhow!("Invalid authorization. Something went wrong. Capability resource is not a DID."))
    }
}

//-------//
// TESTS //
//-------//

#[cfg(test)]
mod tests {
    use super::*;

    use fission_core::ed_did_key::EdDidKey;
    use rs_ucan::builder::UcanBuilder;
    use testresult::TestResult;

    #[test_log::test(tokio::test)]
    async fn validation_test() -> TestResult {
        let issuer = &EdDidKey::generate();
        let ucan: Ucan = UcanBuilder::default()
            .for_audience("did:web:runfission.com")
            .with_lifetime(100)
            .sign(issuer)?;

        let authority = Authority {
            ucan,
            proofs: vec![],
        };

        assert!(authority.validate("did:web:runfission.com").is_ok());

        Ok(())
    }

    #[test_log::test(tokio::test)]
    #[ignore]
    async fn invalid_ucan_test() {
        panic!("pending")
    }

    #[test_log::test(tokio::test)]
    #[ignore]
    async fn incomplete_proofs_test() {
        panic!("pending")
    }

    #[test_log::test(tokio::test)]
    #[ignore]
    async fn invalid_delegation_test() {
        panic!("pending")
    }
}
