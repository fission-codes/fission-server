//! Main fission-cli command line entry points
use crate::{
    paths::config_file,
    responses::{AccountCreationResponse, AccountInfo},
    settings::Settings,
    ucan::{encode_ucan_header, find_delegation_chain},
};
use anyhow::{anyhow, bail, Result};
use clap::{Parser, Subcommand};
use ed25519::pkcs8::{spki::der::pem::LineEnding, DecodePrivateKey, EncodePrivateKey};
use fission_core::{
    capabilities::{did::Did, fission::FissionAbility, indexing::IndexingAbility},
    common::{AccountCreationRequest, EmailVerifyRequest, UcansResponse},
    ed_did_key::EdDidKey,
};
use reqwest::{
    blocking::{Client, RequestBuilder, Response},
    header::CONTENT_TYPE,
    Method,
};
use rs_ucan::{
    builder::UcanBuilder,
    capability::Capability,
    semantics::{ability::Ability, caveat::EmptyCaveat},
    ucan::Ucan,
};
use std::{
    fmt::Debug,
    fs::{create_dir_all, OpenOptions},
    io::Read,
    path::PathBuf,
};
use url::Url;

#[derive(Debug, Parser)]
#[command(name = "fission")]
#[command(about = "Manage your fission account from the command line")]
pub struct Cli {
    #[arg(long, help = "Path to a .pem file with the secret key for this device")]
    key_file: Option<PathBuf>,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Account and login management commands
    Account(Account),
    /// Print file paths used by the application (e.g. the path to config)
    Paths,
}

#[derive(Debug, Parser)]
pub struct Account {
    #[command(subcommand)]
    command: AccountCommands,
}

#[derive(Debug, Subcommand)]
pub enum AccountCommands {
    /// Create a new fission account (even if you already have one)
    Create,
    /// List fission accounts that you currently have access on from this device
    List,
    /// Give one of your accounts a new name
    Rename(RenameCommand),
    /// Delete one of your accounts
    Delete(DeleteCommand),
}

#[derive(Debug, Parser)]
pub struct RenameCommand {
    /// Username of the account to rename.
    /// If not provided, it's assumed you only have access to one account.
    username: Option<String>,
}

#[derive(Debug, Parser)]
pub struct DeleteCommand {
    /// Username of the account to delete.
    /// If not provided, it's assumed you only have access to one account.
    username: Option<String>,
}

impl Cli {
    pub fn run(&self, mut settings: Settings) -> Result<()> {
        if let Some(key_file) = &self.key_file {
            settings.key_file = key_file.clone();
        }

        match &self.command {
            Commands::Account(account) => {
                let mut state = CliState::load(&settings)?;
                state.fetch_ucans()?;

                match &account.command {
                    AccountCommands::Create => {
                        let account = state.create_account()?;

                        println!("Successfully created your account");

                        tracing::info!(?account, "Created account");
                    }
                    AccountCommands::List => {
                        let accounts = state.find_accounts(state.find_capabilities()?);
                        if accounts.is_empty() {
                            println!("You don't have access to any accounts yet. Use \"fission-cli account create\" to create a new one.");
                        } else {
                            println!(
                                "Here's a list of accounts you have access to from this device:"
                            );

                            for (info, did, _) in accounts {
                                match &info.username {
                                    Some(username) => {
                                        println!("{username}");
                                    }
                                    None => {
                                        println!("Anonymous account with DID {did}.");
                                    }
                                }
                            }
                        }
                    }
                    AccountCommands::Rename(rename) => {
                        let accounts = state.find_accounts(state.find_capabilities()?);

                        let (_info, did, chain) = state.pick_account(
                            accounts,
                            &rename.username,
                            "Which account do you want to rename?",
                        )?;

                        let new_username = inquire::Text::new("Pick a new username:").prompt()?;

                        state.rename_account(did, chain, new_username)?;

                        println!("Successfully changed your username.");
                    }
                    AccountCommands::Delete(delete) => {
                        let accounts = state.find_accounts(state.find_capabilities()?);

                        let (_info, did, chain) = state.pick_account(
                            accounts,
                            &delete.username,
                            "Which account do you want to delete?",
                        )?;

                        state.delete_account(did, chain)?;

                        println!("Successfully deleted your account.");
                    }
                }
            }
            Commands::Paths => {
                println!(
                    "{}",
                    config_file().to_str().expect("non utf8 config file path?")
                );
                println!(
                    "{}",
                    settings.key_file.to_str().expect("non utf8 key file path")
                );
            }
        }

        Ok(())
    }
}

#[derive(Debug)]
pub(crate) struct CliState<'s> {
    pub(crate) settings: &'s Settings,
    pub(crate) key: EdDidKey,
    pub(crate) client: Client,
    pub(crate) server_did: String,
    pub(crate) ucans: Vec<Ucan>,
}

impl<'s> CliState<'s> {
    fn load(settings: &'s Settings) -> Result<Self> {
        let key = load_key(settings)?;

        let client = Client::new();

        let url = Url::parse(&format!("{}/api/v0/server-did", settings.api_endpoint))?;
        tracing::info!(%url, "Fetching server DID");
        let server_did = handle_failure(client.get(url).send()?)?.text()?;
        tracing::info!(%server_did, "Got server DID");

        Ok(Self {
            settings,
            key,
            client,
            server_did,
            ucans: Vec::new(),
        })
    }

    fn device_did(&self) -> Did {
        Did(self.key.did())
    }

    fn fetch_ucans(&mut self) -> Result<()> {
        let (ucan, proofs) = self.issue_ucan(self.device_did(), IndexingAbility::Fetch)?;

        let ucans_response: UcansResponse = handle_failure(
            self.server_request(Method::GET, "/api/v0/capabilities")?
                .bearer_auth(ucan.encode()?)
                .header("ucan", encode_ucan_header(&proofs)?)
                .send()?,
        )?
        .json()?;

        self.ucans.extend(ucans_response.into_unrevoked());

        Ok(())
    }

    fn create_account(&mut self) -> Result<AccountInfo> {
        let email = inquire::Text::new("What's your email address?").prompt()?;

        handle_failure(
            self.server_request(Method::POST, "/api/v0/auth/email/verify")?
                .json(&EmailVerifyRequest {
                    email: email.clone(),
                })
                .send()?,
        )?;

        println!("Successfully requested an email verification code.");

        // TODO verify it's a 6 digit number. Allow retries.
        let code = inquire::Text::new("Please enter the verification code:").prompt()?;

        let (ucan, proofs) = self.issue_ucan(self.device_did(), FissionAbility::AccountCreate)?;

        // TODO Check for availablility. Allow retries.
        let username = inquire::Text::new("Choose a username:").prompt()?;

        let account_creation: AccountCreationResponse = handle_failure(
            self.server_request(Method::POST, "/api/v0/account")?
                .bearer_auth(ucan.encode()?)
                .header("ucan", encode_ucan_header(&proofs)?)
                .header(CONTENT_TYPE, "application/json")
                .json(&AccountCreationRequest {
                    email,
                    username,
                    code: code.trim().to_string(),
                })
                .send()?,
        )?
        .json()?;

        self.ucans.extend(account_creation.ucans);

        Ok(account_creation.account)
    }

    fn find_capabilities(&'s self) -> Result<Vec<(Did, Vec<&'s Ucan>)>> {
        let mut caps = Vec::new();

        for ucan in self.ucans.iter() {
            if ucan.audience() == self.key.did_as_str() {
                tracing::debug!(ucan = ucan.encode()?, "Finding capabilities from UCAN");
                for cap in ucan.capabilities() {
                    let Some(Did(subject_did)) = cap.resource().downcast_ref() else {
                        continue;
                    };

                    let subject_did = Did(subject_did.to_string());

                    tracing::debug!(%subject_did, "Found capability, checking delegation chain");

                    if let Some(chain) = find_delegation_chain(
                        &subject_did,
                        cap.ability(),
                        self.key.did_as_str(),
                        &self.ucans,
                    ) {
                        tracing::debug!("Delegation chain found.");
                        caps.push((subject_did, chain));
                    }
                }
            }
        }

        Ok(caps)
    }

    fn find_accounts<'u>(
        &self,
        caps: Vec<(Did, Vec<&'u Ucan>)>,
    ) -> Vec<(AccountInfo, Did, Vec<&'u Ucan>)> {
        caps.into_iter()
            .map(|(did, chain)| {
                let ucan =
                    self.issue_ucan_with(did.clone(), FissionAbility::AccountRead, &chain)?;

                let response = self
                    .server_request(Method::GET, &format!("/api/v0/account/{did}"))?
                    .bearer_auth(ucan.encode()?)
                    .header("ucan", encode_ucan_header(&chain)?)
                    .send()?;
                let account_info: AccountInfo = response.json()?;

                Ok::<_, anyhow::Error>((account_info, did, chain))
            })
            .filter_map(|e| match e {
                Ok(ok) => Some(ok),
                Err(e) => {
                    tracing::debug!(%e, "Error filtered during find_accounts");
                    None
                }
            })
            .collect::<Vec<_>>()
    }

    fn pick_account<'u>(
        &'u self,
        accounts: Vec<(AccountInfo, Did, Vec<&'u Ucan>)>,
        user_choice: &Option<String>,
        prompt: &str,
    ) -> Result<(AccountInfo, Did, Vec<&Ucan>)> {
        Ok(match user_choice {
            Some(username) => accounts
                .into_iter()
                .find(|(info, _, _)| info.username.as_ref() == Some(username))
                .ok_or_else(|| anyhow!("Couldn't find access to an account with this username."))?,
            None => {
                if accounts.len() > 1 {
                    let account_names = accounts
                        .iter()
                        .map(|(info, Did(did), _)| info.username.as_ref().unwrap_or(did))
                        .collect();
                    let account_name = inquire::Select::new(prompt, account_names)
                        .prompt()?
                        .clone();

                    accounts
                        .into_iter()
                        .find(|(info, Did(did), _)| {
                            info.username.as_ref().unwrap_or(did) == &account_name
                        })
                        .ok_or_else(|| {
                            anyhow!("Something went wrong. Couldn't selected account.")
                        })?
                } else {
                    accounts.into_iter().next().ok_or_else(|| {
                        anyhow!("Please provide the username in the command argument.")
                    })?
                }
            }
        })
    }

    fn rename_account(&self, did: Did, chain: Vec<&Ucan>, new_username: String) -> Result<()> {
        let ucan = self.issue_ucan_with(did, FissionAbility::AccountManage, &chain)?;

        handle_failure(
            self.server_request(
                Method::PATCH,
                &format!("/api/v0/account/username/{new_username}"),
            )?
            .bearer_auth(ucan.encode()?)
            .header("ucan", encode_ucan_header(&chain)?)
            .send()?,
        )?;

        Ok(())
    }

    fn delete_account(&self, did: Did, chain: Vec<&Ucan>) -> Result<()> {
        let ucan = self.issue_ucan_with(did, FissionAbility::AccountDelete, &chain)?;

        handle_failure(
            self.server_request(Method::DELETE, "/api/v0/account")?
                .bearer_auth(ucan.encode()?)
                .header("ucan", encode_ucan_header(&chain)?)
                .send()?,
        )?;

        Ok(())
    }

    fn server_request(&self, method: reqwest::Method, path: &str) -> Result<RequestBuilder> {
        let mut url = Url::parse(&self.settings.api_endpoint)?;
        url.set_path(path);
        tracing::info!(url = %url.to_string(), "Building server request");
        Ok(self.client.request(method, url))
    }

    fn issue_ucan(
        &self,
        subject_did: Did,
        ability: impl Ability + Debug,
    ) -> Result<(Ucan, Vec<&Ucan>)> {
        let Some(chain) =
            find_delegation_chain(&subject_did, &ability, self.key.did_as_str(), &self.ucans)
        else {
            bail!("Couldn't find proof for ability {ability} on subject {subject_did}");
        };

        let ucan = self.issue_ucan_with(subject_did, ability, &chain)?;

        Ok((ucan, chain))
    }

    fn issue_ucan_with(
        &self,
        subject_did: Did,
        ability: impl Ability,
        chain: &[&Ucan],
    ) -> Result<Ucan> {
        let mut builder = UcanBuilder::default()
            .for_audience(&self.server_did)
            .with_lifetime(360)
            .claiming_capability(Capability::new(subject_did, ability, EmptyCaveat));

        if let Some(first) = chain.first() {
            builder = builder.witnessed_by(first, None);
        }

        Ok(builder.sign(&self.key)?)
    }
}

fn load_key(settings: &Settings) -> Result<EdDidKey> {
    let key_path = &settings.key_file;

    if let Some(dir) = key_path.parent() {
        create_dir_all(dir)?;
    }

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(key_path)?;

    let file_meta = file.metadata()?;
    let key = if file_meta.len() == 0 {
        tracing::info!(?key_path, "Empty key file, generating new key");
        let key = EdDidKey::generate();
        tracing::info!(%key, "New key generated, writing it back.");
        key.write_pkcs8_pem_file(key_path, LineEnding::default())?;
        tracing::info!(?key_path, "Wrote PKCS8 private key.");
        key
    } else {
        tracing::info!(?key_path, "Key file non-empty, loading key");
        let mut string = String::with_capacity(file_meta.len() as usize);
        file.read_to_string(&mut string)?;
        EdDidKey::from_pkcs8_pem(&string)?
    };
    tracing::info!(%key, "Generated or loaded DID");
    Ok(key)
}

fn handle_failure(response: Response) -> Result<Response> {
    tracing::debug!(?response, "Got server response");

    if !response.status().is_success() {
        let response_info = response
            .text()
            .ok()
            .map_or_else(String::new, |t| format!(": {t}"));
        bail!("Last request was erroneous{}", response_info);
    }

    Ok(response)
}
