//! Authority struct and functions

use crate::{
    app_state::AppState,
    db,
    db::Conn,
    error::{AppError, AppResult},
    models::revocation::find_revoked_subset,
    setups::ServerSetup,
};
use anyhow::{bail, Result};
use fission_core::{
    capabilities::did::Did,
    revocation::{canonical_cid, Revocation},
};
use http::StatusCode;
use libipld::{raw::RawCodec, Ipld};
use rs_ucan::{
    did_verifier::DidVerifierMap,
    semantics::ability::Ability,
    store::{InMemoryStore, Store},
    ucan::Ucan,
    DefaultFact,
};
use serde::de::DeserializeOwned;
use std::collections::BTreeSet;

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
    /// Validate the authority audience
    pub fn validate_audience(&self, intended_audience: &str) -> Result<()> {
        let audience = self.ucan.audience();
        if audience != intended_audience {
            tracing::error!(
                audience = %audience,
                expected = %intended_audience,
                token = ?self.ucan.encode(),
                "Auth token audience doesn't match server DID"
            );
            bail!("Auth token audience doesn't match server DID. Expected {intended_audience}, but got {audience}.")
        }

        Ok(())
    }

    /// Validate an attempt to create a revocation.
    ///
    /// The revoked UCAN needs to be specified using the main `authorization` header
    /// and any proofs needed to verify the revocation, including the proof that
    /// was originally issued by the revocation's issuer and all proofs in between
    /// the authorization UCAN and that one need to be provided in the `ucans` header.
    ///
    /// The UCAN from the `authorization`'s canonical CID needs to match the revocation's
    /// CID.
    pub fn validate_revocation(&self, revocation: &Revocation) -> AppResult<()> {
        let mut store = InMemoryStore::<RawCodec>::default();

        for proof in &self.proofs {
            store.write(Ipld::Bytes(proof.encode()?.as_bytes().to_vec()), None)?;
        }

        revocation
            .verify_valid(&self.ucan, &DidVerifierMap::default(), &store)
            .map_err(|e| AppError::new(StatusCode::FORBIDDEN, Some(e)))
    }

    /// find the set of UCAN canonical CIDs that are revoked and relevant to this request
    pub async fn get_relevant_revocations(&self, conn: &mut Conn<'_>) -> Result<BTreeSet<String>> {
        let mut canonical_cids = BTreeSet::from([canonical_cid(&self.ucan)?]);

        for proof in &self.proofs {
            // This is duplicating work in the usual case, but also it's not *too bad*.
            canonical_cids.insert(canonical_cid(proof)?);
        }

        find_revoked_subset(canonical_cids, conn).await
    }

    /// Validates whether or not the UCAN and proofs have the capability to
    /// perform the given action, with the given issuer as the root of that
    /// authority.
    pub async fn get_capability<S: ServerSetup>(
        &self,
        app_state: &AppState<S>,
        ability: impl Ability,
    ) -> AppResult<Did> {
        self.validate_audience(app_state.server_keypair.did_as_str())?;

        let revocations = self
            .get_relevant_revocations(&mut db::connect(&app_state.db_pool).await?)
            .await?;

        if revocations.contains(&canonical_cid(&self.ucan)?) {
            return Err(AppError::new(
                StatusCode::FORBIDDEN,
                Some("Invocation UCAN was revoked"),
            ));
        }

        let current_time = rs_ucan::time::now();

        let mut store = InMemoryStore::<RawCodec>::default();

        for proof in &self.proofs {
            // TODO(matheus23): rs-ucan should probably have support for revoked CIDs
            if revocations.contains(&canonical_cid(proof)?) {
                continue; // This CID was revoked.
            }
            // TODO(matheus23): we assume SHA2-256 atm. The spec says to hash with all CID formats used in proofs >.<
            store.write(Ipld::Bytes(proof.encode()?.as_bytes().to_vec()), None)?;
        }

        let caps = self.ucan.capabilities().collect::<Vec<_>>();
        let [cap] = caps[..] else {
            if caps.is_empty() {
                tracing::error!("No capabilities provided.");
                return Err(AppError::new(
                    StatusCode::BAD_REQUEST,
                    Some("Invocation UCAN without capabilities provided."),
                ));
            }
            tracing::error!(caps = ?caps, "Invocation UCAN with multiple capabilities is ambiguous.");
            return Err(AppError::new(
                StatusCode::BAD_REQUEST,
                Some("Invocation UCAN with multiple capabilities is ambiguous."),
            ));
        };

        if !cap.ability().is_valid_attenuation(&ability) {
            return Err(AppError::new(
                StatusCode::FORBIDDEN,
                Some(format!(
                    "Invalid authorization. Expected ability {ability}, but got {}",
                    cap.ability()
                )),
            ));
        }

        let Some(Did(did)) = cap.resource().downcast_ref() else {
            return Err(AppError::new(
                StatusCode::BAD_REQUEST,
                Some(format!(
                    "Invalid authorization. Expected resource to be DID, but got {}",
                    cap.resource()
                )),
            ));
        };

        let ability_str = ability.to_string();

        let caps = self
            .ucan
            .capabilities_for(
                did,
                Did(did.clone()),
                ability,
                current_time,
                &DidVerifierMap::default(),
                &store,
            )
            .map_err(|e| AppError::new(StatusCode::FORBIDDEN, Some(e)))?;

        // TODO(matheus23): Not yet handling caveats.
        caps.first()
            .ok_or_else(|| {
                AppError::new(StatusCode::FORBIDDEN, Some(format!(
                    "Invalid authorization. Couldn't find proof for {ability_str} as issued from {did}"
                )))
            })?
            .resource()
            .downcast_ref()
            .cloned()
            .ok_or_else(|| AppError::new(StatusCode::BAD_REQUEST, Some("Invalid authorization. Something went wrong. Capability resource is not a DID.")))
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

        assert!(authority
            .validate_audience("did:web:runfission.com")
            .is_ok());

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
