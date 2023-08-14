//! Authority struct and functions

use fission_core::authority::key_material::SUPPORTED_KEYS;
use std::time::{SystemTime, UNIX_EPOCH};
use ucan::crypto::did::DidParser;

use ucan::store::{MemoryStore, UcanJwtStore};

use ucan::capability::CapabilitySemantics;

///////////
// TYPES //
///////////

#[derive(Debug, Clone)]
/// Represents the authority of an incoming request
pub struct Authority {
    /// https://github.com/ucan-wg/ucan-as-bearer-token#21-entry-point
    pub ucan: ucan::Ucan,
    /// proofs from `ucan` header
    pub proofs: Vec<ucan::Ucan>,
}

/////////////////////
// IMPLEMENTATIONS //
/////////////////////

impl Authority {
    /// Validate an authority struct
    pub async fn validate(&self) -> Result<(), String> {
        let mut did_parser = DidParser::new(SUPPORTED_KEYS);
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|t| t.as_secs());

        ucan::Ucan::validate(&self.ucan, current_time, &mut did_parser)
            .await
            .map_err(|err| err.to_string())
    }

    /// Validates whether or not the UCAN and proofs have the capability to
    /// perform the given action, with the given issuer as the root of that
    /// authority.
    pub async fn has_capability(
        &self,
        with: &str,
        can: &str,
        issuer_did: &str,
    ) -> Result<bool, String> {
        let mut did_parser = DidParser::new(SUPPORTED_KEYS);
        let mut store = MemoryStore::default();
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|t| t.as_secs());

        println!("over here");

        for proof in &self.proofs {
            if let Ok(ucan_str) = proof.encode() {
                tracing::debug!("Adding proof: {}", ucan_str);
                store
                    .write_token(&ucan_str)
                    .await
                    .map_err(|err| err.to_string())?;
            }
        }

        println!("whee");

        let my_ucan = self.ucan.clone();
        let chain =
            ucan::chain::ProofChain::from_ucan(my_ucan, current_time, &mut did_parser, &store)
                .await
                .map_err(|err| err.to_string())?;

        println!("nope");

        let capability_infos =
            chain.reduce_capabilities(&fission_core::capabilities::delegation::SEMANTICS);

        println!("here?");

        let expected_capability = fission_core::capabilities::delegation::SEMANTICS
            .parse(with, can)
            .unwrap();

        println!("the unwrap screwed us");

        for info in capability_infos {
            println!("in this thing");
            tracing::debug!("Checking capabilities: {:?} {}", info, issuer_did);
            if info.originators.contains(issuer_did)
                && info.capability.enables(&expected_capability)
            {
                return Ok(true);
            }
        }

        println!("returning normally no access");
        Ok(false)
    }
}

///////////
// TESTS //
///////////

#[cfg(test)]
mod tests {
    use super::*;
    use fission_core::authority::key_material::{generate_ed25519_material, SERVER_DID};
    use ucan::builder::UcanBuilder;

    #[tokio::test]
    async fn validation_test() {
        let issuer = generate_ed25519_material();
        let ucan = UcanBuilder::default()
            .issued_by(&issuer)
            .for_audience(SERVER_DID)
            .with_lifetime(100)
            .build()
            .unwrap()
            .sign()
            .await
            .unwrap();

        let authority = Authority {
            ucan,
            proofs: vec![],
        };

        assert!(authority.validate().await.is_ok());
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
