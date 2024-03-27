//! Utilities for testing (TODO this should be a temporary module. Let's figure out simpler APIs, perhaps builders, etc. for rs-ucan)
use anyhow::Result;
use libipld::Ipld;
use rand::rngs::OsRng;
use std::{collections::BTreeMap, time::SystemTime};
use ucan::{
    ability::{arguments::Named, command::ToCommand, parse::ParseAbility},
    crypto::varsig::{self, header::EdDsaHeader},
    delegation::{self, store::Store},
    did::preset::{Signer, Verifier},
    invocation::{self, Agent},
    time::Timestamp,
    Delegation,
};

/// The dag-cbor varsig header
pub fn varsig_header() -> varsig::header::Preset {
    varsig::header::Preset::EdDsa(EdDsaHeader {
        codec: varsig::encoding::Preset::DagCbor,
    })
}

/// Setup a simple agent that can delegate and invoke
pub fn setup_agents<T: ToCommand + Clone + ParseAbility>(
    delegation_store: &delegation::store::MemoryStore,
) -> (
    Agent<invocation::store::MemoryStore<T>, &'_ delegation::store::MemoryStore, T>,
    delegation::Agent<&'_ delegation::store::MemoryStore>,
)
where
    Named<Ipld>: From<T>,
{
    let sk = ed25519_dalek::SigningKey::generate(&mut OsRng);
    let did = Verifier::Key(ucan::did::key::Verifier::EdDsa(sk.verifying_key()));
    let signer = Signer::Key(ucan::did::key::Signer::EdDsa(sk));
    let inv_store = invocation::store::MemoryStore::<T>::default();
    let invocation_agent = Agent::new(did.clone(), signer.clone(), inv_store, delegation_store);
    let delegation_agent = delegation::Agent::new(did, signer, delegation_store);
    (invocation_agent, delegation_agent)
}

/// Setup a simple agent that can only invoke
pub fn setup_invocation_agent<T: ToCommand + Clone + ParseAbility>(
) -> Agent<invocation::store::MemoryStore<T>, delegation::store::MemoryStore, T>
where
    Named<Ipld>: From<T>,
{
    let sk = ed25519_dalek::SigningKey::generate(&mut OsRng);
    let did = Verifier::Key(ucan::did::key::Verifier::EdDsa(sk.verifying_key()));
    let signer = Signer::Key(ucan::did::key::Signer::EdDsa(sk));
    let inv_store = invocation::store::MemoryStore::<T>::default();
    Agent::new(
        did.clone(),
        signer.clone(),
        inv_store,
        delegation::store::MemoryStore::default(),
    )
}

/// Create a delegation from a delegation agent
pub fn create_delegation(
    from: &delegation::Agent<&delegation::store::MemoryStore>,
    to: &ucan::did::preset::Verifier,
    subject: Option<&ucan::did::preset::Verifier>,
    cmd: &str,
) -> Result<Delegation> {
    let ucan = from.delegate(
        to.clone(),
        subject,
        None,
        cmd.to_string(),
        Vec::new(),
        BTreeMap::new(),
        Timestamp::five_years_from_now(),
        None,
        SystemTime::now(),
        varsig_header(),
    )?;

    Ok(ucan)
}

/// Create and store a delegation from given agent in given delegation store
pub fn delegate(
    delegations: &delegation::store::MemoryStore,
    from: &delegation::Agent<&delegation::store::MemoryStore>,
    to: &ucan::did::preset::Verifier,
    subject: Option<&ucan::did::preset::Verifier>,
    cmd: &str,
) -> Result<()> {
    let ucan = create_delegation(from, to, subject, cmd)?;
    delegations.insert(ucan)?;
    Ok(())
}
