//! Authority struct and functions

use anyhow::Result;
use did_key::{Ed25519KeyPair, Fingerprint};
use ed25519_dalek::SigningKey;
use libipld::{raw::RawCodec, Ipld};
use rand::thread_rng;
use rs_ucan::{
    builder::DEFAULT_MULTIHASH,
    crypto::eddsa::ed25519_dalek_verifier,
    did_verifier::{did_key::DidKeyVerifier, DidVerifierMap},
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
        issuer: String,
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

pub(crate) fn generate_ed25519_issuer() -> (String, SigningKey) {
    let key = ed25519_dalek::SigningKey::generate(&mut thread_rng());
    let did_key_str = format!(
        "did:key:{}",
        Ed25519KeyPair::from_public_key(key.verifying_key().as_bytes()).fingerprint()
    );
    (did_key_str, key)
}

pub(crate) fn did_verifier_map() -> DidVerifierMap {
    let mut did_key_verifier = DidKeyVerifier::default();
    did_key_verifier.set::<ed25519::Signature, _>(ed25519_dalek_verifier);

    let mut did_verifier_map = DidVerifierMap::default();
    did_verifier_map.register(did_key_verifier);
    did_verifier_map
}

//-------//
// TESTS //
//-------//

#[cfg(test)]
mod tests {
    use super::*;

    use rs_ucan::builder::UcanBuilder;

    #[tokio::test]
    async fn validation_test() {
        let (issuer, key) = generate_ed25519_issuer();
        let ucan: Ucan = UcanBuilder::default()
            .issued_by(issuer)
            .for_audience("did:web:runfission.com")
            .with_lifetime(100)
            .sign(&key)
            .unwrap();

        let authority = Authority {
            ucan,
            proofs: vec![],
        };

        assert!(authority.validate(&did_verifier_map()).is_ok());
    }

    #[tokio::test]
    #[ignore]
    async fn invalid_ucan_test() {
        panic!("pending")
    }

    #[tokio::test]
    #[ignore]
    async fn incomplete_proofs_test() {
        panic!("pending")
    }

    #[tokio::test]
    #[ignore]
    async fn invalid_delegation_test() {
        panic!("pending")
    }
}
