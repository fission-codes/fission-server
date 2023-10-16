//! Authority struct and functions

use anyhow::Result;
use libipld::{raw::RawCodec, Ipld};
use rs_ucan::{
    builder::DEFAULT_MULTIHASH,
    did_verifier::DidVerifierMap,
    semantics::{ability::Ability, resource::Resource},
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
    pub fn validate(&self, did_verifier_map: &DidVerifierMap) -> Result<()> {
        self.ucan.validate(rs_ucan::time::now(), did_verifier_map)?;

        Ok(())
    }

    /// Validates whether or not the UCAN and proofs have the capability to
    /// perform the given action, with the given issuer as the root of that
    /// authority.
    pub fn has_capability(
        &self,
        resource: impl Resource,
        ability: impl Ability,
        issuer: impl AsRef<str>,
        did_verifier_map: &DidVerifierMap,
    ) -> Result<bool> {
        let current_time = rs_ucan::time::now();

        let mut store = InMemoryStore::<RawCodec>::default();

        for proof in &self.proofs {
            // TODO(matheus23): we assume SHA2-256 atm. The spec says to hash with all CID formats used in proofs >.<
            store.write(
                Ipld::Bytes(proof.encode()?.as_bytes().to_vec()),
                DEFAULT_MULTIHASH,
            )?;
        }

        let caps = self.ucan.capabilities_for(
            issuer,
            resource,
            ability,
            current_time,
            did_verifier_map,
            &store,
        )?;

        // TODO(matheus23): Not yet handling caveats.
        Ok(!caps.is_empty())
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
            .issued_by(issuer)
            .for_audience("did:web:runfission.com")
            .with_lifetime(100)
            .sign(issuer)?;

        let authority = Authority {
            ucan,
            proofs: vec![],
        };

        assert!(authority.validate(&DidVerifierMap::default()).is_ok());

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
