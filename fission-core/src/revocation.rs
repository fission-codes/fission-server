//! UCAN revocation implementation (Section 6.6 in the UCAN 0.10 spec)

use crate::ed_did_key::EdDidKey;
use anyhow::{anyhow, bail, Result};
use libipld::{multibase::Base, multihash::Code, raw::RawCodec, Ipld};
use rs_ucan::{
    capability::CapabilityParser, did_verifier::DidVerifierMap, store::Store, ucan::Ucan,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use signature::Signer;
use std::{collections::VecDeque, str::FromStr};
use utoipa::ToSchema;

/// The revocation record from the UCAN 0.10 spec:
/// https://github.com/ucan-wg/spec/tree/16ee2ce7815c60a0ea870283d3b53ddcb3043c02#66-revocation
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Revocation {
    /// The issuer of the revocation
    pub iss: String,
    /// The CID of the UCAN that's revoked
    pub revoke: String,
    /// The signature of `REVOKE:<revoke>`
    pub challenge: String,
}

impl Revocation {
    /// Create a revocation record for given UCAN, issued by given issuer.
    pub fn new<F, C>(issuer: &EdDidKey, ucan: &Ucan<F, C>) -> Result<Self>
    where
        F: Clone + DeserializeOwned,
        C: CapabilityParser,
    {
        let iss = issuer.did();
        let revoke = canonical_cid(ucan)?;

        let signature = issuer.sign(format!("REVOKE:{revoke}").as_bytes());
        let challenge = data_encoding::BASE64_NOPAD.encode(&signature.to_vec());

        Ok(Self {
            iss,
            revoke,
            challenge,
        })
    }

    /// Verify the validity of a revocation.
    pub fn verify_signed(&self, did_verifier_map: &DidVerifierMap) -> Result<()> {
        let (method, identifier) = self
            .iss
            .strip_prefix("did:")
            .and_then(|did| did.split_once(':'))
            .ok_or(anyhow!(
                "expected did:<method>:<identifier>, got {}",
                self.iss
            ))?;

        let revoke = &self.revoke;
        let revoke_str = format!("REVOKE:{revoke}");
        let signed_data = revoke_str.as_bytes();
        let signature = data_encoding::BASE64_NOPAD.decode(self.challenge.as_bytes())?;

        did_verifier_map.verify(method, identifier, signed_data, &signature)?;

        Ok(())
    }

    /// Verify whether a revocation issuing was valid, given some UCAN proofs
    pub fn verify_valid<F, C, S>(
        &self,
        ucan: &Ucan<F, C>,
        did_verifier_map: &DidVerifierMap,
        store: &S,
    ) -> Result<()>
    where
        F: Clone + DeserializeOwned,
        C: CapabilityParser,
        S: Store<RawCodec, Error = anyhow::Error>,
    {
        if self.revoke != canonical_cid(ucan)? {
            bail!("Revocation CID doesn't match provided UCAN");
        }

        self.verify_signed(did_verifier_map)?;

        let mut current_proofs = VecDeque::from([ucan.clone()]);
        while let Some(proof) = current_proofs.pop_front() {
            if proof.issuer() == self.iss {
                // We found a UCAN in the chain that was issued by the issuer of the revocation.
                return Ok(());
            }

            for proof_cid in proof.proofs().unwrap_or(vec![]) {
                match store.read::<Ipld>(proof_cid)? {
                    Some(Ipld::Bytes(bytes)) => {
                        let token = String::from_utf8(bytes)?;
                        let proof_ucan = Ucan::<F, C>::from_str(&token)?;
                        current_proofs.push_back(proof_ucan);
                    }
                    Some(ipld) => bail!(
                        "Unexpected IPLD format in proof store (cid: {proof_cid}): Expected Bytes, but got {ipld:?}"
                    ),
                    // If we can't find a proof CID, it's fine, we just skip, there may be another path to
                    // a UCAN from the issuer of the revocation.
                    None => tracing::warn!(%proof_cid, "Missing proof CID in revoked UCAN's proof tree"),
                }
            }
        }

        Err(anyhow!(
            "Revocation issuer is not part of the issuer proof chain"
        ))
    }
}

/// Returns the "canonical CID" of a UCAN.
/// That is the CID of a UCAN with a raw codec, sha-256 hash and base32-encoded.
pub fn canonical_cid<F, C>(ucan: &Ucan<F, C>) -> Result<String>
where
    F: Clone + DeserializeOwned,
    C: CapabilityParser,
{
    Ok(ucan
        .to_cid(Some(Code::Sha2_256))?
        .to_string_of_base(Base::Base32Lower)?)
}

#[cfg(test)]
mod tests {
    use super::Revocation;
    use crate::ed_did_key::EdDidKey;
    use assert_matches::assert_matches;
    use libipld::{raw::RawCodec, Ipld};
    use rs_ucan::{
        builder::UcanBuilder,
        store::{InMemoryStore, Store},
        ucan::Ucan,
    };
    use testresult::TestResult;

    #[test_log::test]
    fn new_revocation_is_signed() -> TestResult {
        let issuer = EdDidKey::generate();
        let ucan: Ucan = UcanBuilder::default()
            .for_audience("did:web:example.com")
            .sign(&issuer)?;
        let revocation = Revocation::new(&issuer, &ucan)?;

        assert_matches!(revocation.verify_signed(&Default::default()), Ok(_));

        Ok(())
    }

    #[test_log::test]
    fn wrong_issuer_revocation_isnt_signed() -> TestResult {
        let issuer = EdDidKey::generate();
        let ucan: Ucan = UcanBuilder::default()
            .for_audience("did:web:example.com")
            .sign(&issuer)?;
        let mut revocation = Revocation::new(&issuer, &ucan)?;

        revocation.iss = EdDidKey::generate().did();

        assert_matches!(revocation.verify_signed(&Default::default()), Err(_));

        Ok(())
    }

    #[test_log::test]
    fn revocation_is_valid_from_issuer_in_chain() -> TestResult {
        let alice = &EdDidKey::generate();
        let bob = &EdDidKey::generate();
        let carol = &EdDidKey::generate();

        let proof: Ucan = UcanBuilder::default().for_audience(bob).sign(alice)?;
        let ucan: Ucan = UcanBuilder::default()
            .for_audience(carol)
            .witnessed_by(&proof, None)
            .sign(bob)?;

        let mut store = InMemoryStore::<RawCodec>::default();
        store.write(Ipld::Bytes(proof.encode()?.as_bytes().to_vec()), None)?;

        let rev_alice = Revocation::new(alice, &ucan)?;
        assert_matches!(
            rev_alice.verify_valid(&ucan, &Default::default(), &store),
            Ok(_) // Alice should be able to revoke the final UCAN "from the distance"
        );

        let rev_bob = Revocation::new(bob, &ucan)?;
        assert_matches!(
            rev_bob.verify_valid(&ucan, &Default::default(), &store),
            Ok(_) // Bob should be able to revoke the final UCAN
        );

        let rev_carol = Revocation::new(carol, &ucan)?;
        assert_matches!(
            rev_carol.verify_valid(&ucan, &Default::default(), &store),
            Err(_) // Carol shouldn't be able to revoke the UCAN. She's not part of the chain of issuers.
        );

        Ok(())
    }
}
