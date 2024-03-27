//! UCAN 1.0 capabilities used in the fission server (TODO: adjust docs once the upgrade is complete)

use libipld::Ipld;
use serde::Serialize;
use ucan::ability::{
    arguments::Named,
    command::{Command, ToCommand},
    parse::{ParseAbility, ParseAbilityError},
};

/// All account-related abilities
#[derive(Debug, Clone, PartialEq)]
pub enum FissionAbility {
    /// Account creation
    AccountCreate(CmdAccountCreate),
    /// Anything noncritical
    AccountNoncritical(AccountNoncritical),
    /// General account management
    AccountManage(CmdAccountManage),
    /// Account deletion
    AccountDelete(CmdAccountDelete),
    /// Account linking
    AccountLink(CmdAccountLink),
    /// Capability fetching
    CapabilityFetch(CmdCapabilityFetch),
}

/// All non-critical account abilities
#[derive(Debug, Clone, PartialEq)]
pub enum AccountNoncritical {
    /// Account information
    Info(CmdAccountInfo),
}

/// The `/account/create` command
#[derive(Debug, Clone, PartialEq)]
pub struct CmdAccountCreate;

impl Command for CmdAccountCreate {
    const COMMAND: &'static str = "/account/create";
}

impl From<CmdAccountCreate> for FissionAbility {
    fn from(cmd: CmdAccountCreate) -> Self {
        FissionAbility::AccountCreate(cmd)
    }
}

/// The `/account/noncritical/info` command
#[derive(Debug, Clone, PartialEq)]
pub struct CmdAccountInfo;

impl Command for CmdAccountInfo {
    const COMMAND: &'static str = "/account/noncritical/info";
}

impl From<CmdAccountInfo> for FissionAbility {
    fn from(cmd: CmdAccountInfo) -> Self {
        FissionAbility::AccountNoncritical(AccountNoncritical::Info(cmd))
    }
}

/// The `/account/manage` command
#[derive(Debug, Clone, PartialEq)]
pub struct CmdAccountManage;

impl Command for CmdAccountManage {
    const COMMAND: &'static str = "/account/manage";
}

impl From<CmdAccountManage> for FissionAbility {
    fn from(cmd: CmdAccountManage) -> Self {
        FissionAbility::AccountManage(cmd)
    }
}

/// The `/account/delete` command
#[derive(Debug, Clone, PartialEq)]
pub struct CmdAccountDelete;

impl Command for CmdAccountDelete {
    const COMMAND: &'static str = "/account/delete";
}

impl From<CmdAccountDelete> for FissionAbility {
    fn from(cmd: CmdAccountDelete) -> Self {
        FissionAbility::AccountDelete(cmd)
    }
}

/// The `/account/link` command
#[derive(Debug, Clone, PartialEq)]
pub struct CmdAccountLink;

impl Command for CmdAccountLink {
    const COMMAND: &'static str = "/account/link";
}

impl From<CmdAccountLink> for FissionAbility {
    fn from(cmd: CmdAccountLink) -> Self {
        FissionAbility::AccountLink(cmd)
    }
}

/// The `/capability/fetch` command
#[derive(Debug, Clone, PartialEq)]
pub struct CmdCapabilityFetch;

impl Command for CmdCapabilityFetch {
    const COMMAND: &'static str = "/capability/fetch";
}

impl From<CmdCapabilityFetch> for FissionAbility {
    fn from(cmd: CmdCapabilityFetch) -> Self {
        FissionAbility::CapabilityFetch(cmd)
    }
}

//
// Ability implementations
//

impl ToCommand for AccountNoncritical {
    fn to_command(&self) -> String {
        match self {
            Self::Info(info) => info.to_command(),
        }
    }
}

impl ToCommand for FissionAbility {
    fn to_command(&self) -> String {
        match self {
            Self::AccountCreate(create) => create.to_command(),
            Self::AccountNoncritical(noncritical) => noncritical.to_command(),
            Self::AccountManage(manage) => manage.to_command(),
            Self::AccountDelete(delete) => delete.to_command(),
            Self::AccountLink(link) => link.to_command(),
            Self::CapabilityFetch(fetch) => fetch.to_command(),
        }
    }
}

impl ParseAbility for FissionAbility {
    type ArgsErr = ();

    fn try_parse(cmd: &str, _: Named<Ipld>) -> Result<Self, ParseAbilityError<Self::ArgsErr>> {
        match cmd {
            CmdAccountCreate::COMMAND => Ok(FissionAbility::AccountCreate(CmdAccountCreate)),
            CmdAccountInfo::COMMAND => Ok(FissionAbility::AccountNoncritical(
                AccountNoncritical::Info(CmdAccountInfo),
            )),
            CmdAccountLink::COMMAND => Ok(FissionAbility::AccountLink(CmdAccountLink)),
            CmdAccountDelete::COMMAND => Ok(FissionAbility::AccountDelete(CmdAccountDelete)),
            CmdAccountManage::COMMAND => Ok(FissionAbility::AccountManage(CmdAccountManage)),
            CmdCapabilityFetch::COMMAND => Ok(FissionAbility::CapabilityFetch(CmdCapabilityFetch)),
            _ => Err(ParseAbilityError::UnknownCommand(cmd.to_string())),
        }
    }
}

impl From<FissionAbility> for Named<Ipld> {
    fn from(_: FissionAbility) -> Self {
        // No fields yet
        Named::new()
    }
}

impl Serialize for FissionAbility {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let ipld: Named<Ipld> = self.clone().into();
        ipld.serialize(serializer)
    }
}

#[cfg(test)]
mod tests {
    use super::{CmdAccountCreate, CmdAccountManage};
    use crate::{
        caps::{CmdAccountInfo, FissionAbility},
        test_utils::{delegate, setup_agents, varsig_header},
    };
    use assert_matches::assert_matches;
    use std::{collections::BTreeMap, convert::Infallible, time::SystemTime};
    use testresult::TestResult;
    use ucan::{
        delegation::{self},
        invocation::{
            self,
            agent::{InvokeError, Recipient},
            Agent,
        },
        Invocation,
    };

    fn simulate_create_account<'a>(
        delegations: &'a delegation::store::MemoryStore,
        client: &Agent<
            invocation::store::MemoryStore<FissionAbility>,
            &delegation::store::MemoryStore,
            FissionAbility,
        >,
        server: &Agent<
            invocation::store::MemoryStore<FissionAbility>,
            &delegation::store::MemoryStore,
            FissionAbility,
        >,
        server_del: &delegation::Agent<&'_ delegation::store::MemoryStore>,
        subject: &ucan::did::preset::Verifier,
    ) -> TestResult<(
        Agent<
            invocation::store::MemoryStore<FissionAbility>,
            &'a delegation::store::MemoryStore,
            FissionAbility,
        >,
        delegation::Agent<&'a delegation::store::MemoryStore>,
    )> {
        let create_invocation = client.invoke(
            Some(server.did.clone()),
            subject.clone(),
            FissionAbility::AccountCreate(CmdAccountCreate),
            BTreeMap::new(),
            None,
            None,
            None,
            SystemTime::now(),
            varsig_header(),
        )?;

        // The sever receives the invocation and validates it:
        assert_matches!(server.receive(create_invocation)?, Recipient::You(_));

        // Then it creates a new account DID & delegates it to itself & further delegates to the client.
        let (account, account_del) = setup_agents::<FissionAbility>(delegations);

        // Create a delegation from account -> server
        // TODO: Should we make this a powerline eventually?
        delegate(
            delegations,
            &account_del,
            &server.did,
            Some(&account.did),
            "/",
        )?;

        // Delegate from server to the subject that wanted to create the account:
        // TODO: also powerline?
        delegate(delegations, &server_del, subject, Some(&account.did), "/")?;

        Ok((account, account_del))
    }

    fn simulate_account_invocation(
        account: &Agent<
            invocation::store::MemoryStore<FissionAbility>,
            &delegation::store::MemoryStore,
            FissionAbility,
        >,
        client: &Agent<
            invocation::store::MemoryStore<FissionAbility>,
            &delegation::store::MemoryStore,
            FissionAbility,
        >,
        server: &Agent<
            invocation::store::MemoryStore<FissionAbility>,
            &delegation::store::MemoryStore,
            FissionAbility,
        >,
        cmd: FissionAbility,
    ) -> Result<Invocation<FissionAbility>, InvokeError<Infallible>> {
        client.invoke(
            Some(server.did.clone()),
            account.did.clone(),
            cmd,
            BTreeMap::new(),
            None,
            None,
            None,
            SystemTime::now(),
            varsig_header(),
        )
    }

    #[test_log::test]
    fn simulate_account_create_flow() -> TestResult {
        // delegations are simulated to be "public".
        // Any stored delegations are readable by everyone.
        let delegations = &delegation::store::MemoryStore::default();

        let (server, server_del) = setup_agents::<FissionAbility>(delegations);
        let (device, _) = setup_agents::<FissionAbility>(delegations);

        let (account, _) =
            simulate_create_account(delegations, &device, &server, &server_del, &device.did)?;

        // Now, the device should be able to do stuff!

        let info_invocation =
            simulate_account_invocation(&account, &device, &server, CmdAccountInfo.into())?;
        assert_matches!(server.receive(info_invocation), Ok(Recipient::You(_)));

        Ok(())
    }

    #[test_log::test]
    fn simulate_account_delegation_with_restrictions() -> TestResult {
        let delegations = &delegation::store::MemoryStore::default();

        let (server, server_del) = setup_agents::<FissionAbility>(delegations);
        let (device, device_del) = setup_agents::<FissionAbility>(delegations);

        let (account, _) =
            simulate_create_account(delegations, &device, &server, &server_del, &device.did)?;

        // The main device now delegates to a second device which should
        // only have noncritical access
        let (second_device, _) = setup_agents::<FissionAbility>(delegations);
        delegate(
            delegations,
            &device_del,            // from
            &second_device.did,     // to
            Some(&account.did),     // subject
            "/account/noncritical", // command
        )?;

        let second_info_invocation =
            simulate_account_invocation(&account, &second_device, &server, CmdAccountInfo.into())?;

        // info should be a noncritical delegation and thus work
        assert_matches!(
            server.receive(second_info_invocation),
            Ok(Recipient::You(_))
        );

        // Can't delegate /account/manage with only /account/noncritical ability
        assert_matches!(
            simulate_account_invocation(&account, &second_device, &server, CmdAccountManage.into()),
            Err(_)
        );

        Ok(())
    }

    #[test_log::test]
    fn simulate_account_create_with_passkey() -> TestResult {
        let delegations = &delegation::store::MemoryStore::default();

        let (server, server_del) = setup_agents::<FissionAbility>(delegations);
        let (passkey, passkey_del) = setup_agents::<FissionAbility>(delegations);
        let (device, _) = setup_agents::<FissionAbility>(delegations);

        // We create a powerline from passkey to the device - it's allowed to act on its behalf:
        delegate(delegations, &passkey_del, &device.did, None, "/")?;

        // We create an account on behalf of the passkey!
        let (account, _) =
            simulate_create_account(delegations, &device, &server, &server_del, &passkey.did)?;

        // We can now still act as the passkey, even though the subject changed from passkey.did to account.did:
        let info_invocation =
            simulate_account_invocation(&account, &device, &server, CmdAccountInfo.into())?;

        // info should be a noncritical delegation and thus work
        assert_matches!(server.receive(info_invocation), Ok(Recipient::You(_)));

        Ok(())
    }
}
