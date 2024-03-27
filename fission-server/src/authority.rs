//! Authority struct and functions

use crate::{
    app_state::AppState,
    error::{AppError, AppResult},
    setups::ServerSetup,
};
use fission_core::{capabilities::did::Did, caps::FissionAbility, revocation::Revocation};
use http::StatusCode;
use libipld::Ipld;
use ucan::{
    ability::{arguments::Named, command::ToCommand, parse::ParseAbility},
    delegation::{self, store::Store},
    invocation, Delegation, Invocation,
};

//-------//
// TYPES //
//-------//

#[derive(Debug, Clone)]
/// Represents the authority of an incoming request
pub struct Authority<A = FissionAbility> {
    /// https://github.com/ucan-wg/ucan-as-bearer-token#21-entry-point
    pub invocation: Invocation<A>,
    /// proofs from `ucans` header
    pub delegations: Vec<Delegation>,
}

//-----------------//
// IMPLEMENTATIONS //
//-----------------//

impl<A: Clone + PartialEq + ToCommand + ParseAbility> Authority<A>
where
    Named<Ipld>: From<A>,
{
    /// Validate an attempt to create a revocation.
    ///
    /// The revoked UCAN needs to be specified using the main `authorization` header
    /// and any proofs needed to verify the revocation, including the proof that
    /// was originally issued by the revocation's issuer and all proofs in between
    /// the authorization UCAN and that one need to be provided in the `ucans` header.
    ///
    /// The UCAN from the `authorization`'s canonical CID needs to match the revocation's
    /// CID.
    pub fn validate_revocation(&self, _revocation: &Revocation) -> AppResult<()> {
        // TODO
        Ok(())
    }

    /// Validates whether or not the UCAN and proofs have the capability to
    /// perform the given action, with the given issuer as the root of that
    /// authority.
    pub async fn get_capability<S: ServerSetup>(
        self,
        app_state: &AppState<S>,
        ability: A,
    ) -> AppResult<Did> {
        let Self {
            invocation,
            delegations,
        } = self;

        let subject = invocation.subject().to_string();
        if invocation.ability() != &ability {
            return Err(AppError::new(
                StatusCode::FORBIDDEN,
                Some("Incorrect ability in invocation"),
            ));
        }

        let delegation_store = delegation::store::MemoryStore::new();
        for delegation in delegations {
            delegation_store.insert(delegation)?;
        }
        let (signer, did) = app_state.server_keypair.to_ucan_interop();
        let agent = invocation::Agent::<_, _, A>::new(
            did.clone(),
            signer,
            invocation::store::MemoryStore::default(),
            delegation_store,
        );

        let recipient = agent.receive(invocation)?;
        match recipient {
            invocation::agent::Recipient::You(_) => Ok(Did(subject)),
            _ => Err(AppError::new(
                StatusCode::FORBIDDEN,
                Some("Authorization UCAN has incorrect audience."),
            )),
        }
    }
}

//-------//
// TESTS //
//-------//

#[cfg(test)]
mod tests {
    use super::Authority;
    use crate::test_utils::test_context::TestContext;
    use assert_matches::assert_matches;
    use fission_core::{
        caps::{CmdAccountCreate, CmdCapabilityFetch, FissionAbility},
        test_utils::{setup_invocation_agent, varsig_header},
    };
    use std::{collections::BTreeMap, time::SystemTime};
    use testresult::TestResult;

    #[test_log::test(tokio::test)]
    async fn smoke_test() -> TestResult {
        let ctx = &TestContext::new().await?;
        let (_, server_did) = ctx.server_did().to_ucan_interop();
        // create an invocation agent
        let agent = setup_invocation_agent::<FissionAbility>();

        // create an invocation
        let invocation = agent.invoke(
            Some(server_did),
            agent.did.clone(),
            FissionAbility::CapabilityFetch(CmdCapabilityFetch),
            BTreeMap::new(),
            None,
            None,
            None,
            SystemTime::now(),
            varsig_header(),
        )?;

        // create an Authority with only that invocation
        let authority = Authority {
            invocation,
            delegations: Vec::new(),
        };

        // verify that get_capability works
        let result = authority
            .get_capability(
                ctx.app_state(),
                FissionAbility::CapabilityFetch(CmdCapabilityFetch),
            )
            .await;

        assert_matches!(result, Ok(_));

        Ok(())
    }

    #[test_log::test(tokio::test)]
    async fn test_get_mismatching_capability_fails() -> TestResult {
        let ctx = &TestContext::new().await?;
        let (_, server_did) = ctx.server_did().to_ucan_interop();
        let agent = setup_invocation_agent::<FissionAbility>();
        let invocation = agent.invoke(
            Some(server_did),
            agent.did.clone(),
            FissionAbility::CapabilityFetch(CmdCapabilityFetch),
            BTreeMap::new(),
            None,
            None,
            None,
            SystemTime::now(),
            varsig_header(),
        )?;

        let authority = Authority {
            invocation,
            delegations: Vec::new(),
        };

        // we're using a different capability here
        let result = authority
            .get_capability(
                ctx.app_state(),
                FissionAbility::AccountCreate(CmdAccountCreate),
            )
            .await;

        assert_matches!(result, Err(_));

        Ok(())
    }
}
