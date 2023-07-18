//! lifted wholesale from https://github.com/ucan-wg/rs-ucan/blob/71bb83a83fd7c5497ecc68e5f183799e80771caf/ucan/src/tests/fixtures/crypto.rs
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use did_key::{CoreSign, Fingerprint, PatchedKeyPair as _PatchedKeyPair};
use ucan::crypto::KeyMaterial;

/// PatchedKeyPair (see did-key)
#[allow(missing_debug_implementations)]
pub struct PatchedKeyPair(pub _PatchedKeyPair);

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl KeyMaterial for PatchedKeyPair {
    fn get_jwt_algorithm_name(&self) -> String {
        "EdDSA".into()
    }

    async fn get_did(&self) -> Result<String> {
        Ok(format!("did:key:{}", self.0.fingerprint()))
    }

    async fn sign(&self, payload: &[u8]) -> Result<Vec<u8>> {
        Ok(CoreSign::sign(&self.0, payload))
    }

    async fn verify(&self, payload: &[u8], signature: &[u8]) -> Result<()> {
        CoreSign::verify(&self.0, payload, signature).map_err(|error| anyhow!("{:?}", error))
    }
}

// keeping this here for future reference
//
// how to generate a ucan and an ephemeral key to go along with
//
// /// Outputs a UCAN using an ephemeral key (re: _NO SECURITY_) with the
// /// claimed email address as a fact, issued to the requesting entity.
// ///
// /// At some point, this may be modified to use a non-ephemeral key, but
// /// for now
// pub async fn to_ucan(&self) -> Result<String, Error> {
//     let ephemeral_key = generate::<Ed25519KeyPair>(None);
//     let ephemeral_keypair = PatchedKeyPair(ephemeral_key);

//     UcanBuilder::default()
//         .issued_by(&ephemeral_keypair)
//         .for_audience(&self.did)
//         .with_lifetime(60 * 5)
//         .with_fact(json!({"email": self.email.clone()}))
//         .build()?
//         .sign()
//         .await?
//         .encode()
// }
