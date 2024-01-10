//! Main fission-cli command line entry points
use crate::{
    logging::LogAndHandleErrorMiddleware,
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
    dns,
    ed_did_key::EdDidKey,
};
use hickory_proto::rr::RecordType;
use reqwest::{header::CONTENT_TYPE, Client, Method};
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware, RequestBuilder};
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
    pub async fn run(&self, mut settings: Settings) -> Result<()> {
        if let Some(key_file) = &self.key_file {
            settings.key_file = key_file.clone();
        }

        match &self.command {
            Commands::Account(account) => {
                let mut state = CliState::load(&settings).await?;
                state.fetch_ucans().await?;

                match &account.command {
                    AccountCommands::Create => {
                        let account = state.create_account().await?;

                        println!("Successfully created your account");

                        tracing::info!(?account, "Created account");
                    }
                    AccountCommands::List => {
                        let accounts = state.find_accounts(state.find_capabilities()?).await;
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
                        let accounts = state.find_accounts(state.find_capabilities()?).await;

                        let (_info, did, chain) = state.pick_account(
                            accounts,
                            &rename.username,
                            "Which account do you want to rename?",
                        )?;

                        let new_username = inquire::Text::new("Pick a new username:").prompt()?;

                        state.rename_account(did, chain, new_username).await?;

                        println!("Successfully changed your username.");
                    }
                    AccountCommands::Delete(delete) => {
                        let accounts = state.find_accounts(state.find_capabilities()?).await;

                        let (_info, did, chain) = state.pick_account(
                            accounts,
                            &delete.username,
                            "Which account do you want to delete?",
                        )?;

                        state.delete_account(did, chain).await?;

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
    pub(crate) client: ClientWithMiddleware,
    pub(crate) server_did: String,
    pub(crate) ucans: Vec<Ucan>,
}

impl<'s> CliState<'s> {
    async fn load(settings: &'s Settings) -> Result<CliState<'s>> {
        let key = load_key(settings)?;

        let client = Client::new();
        let client = ClientBuilder::new(client)
            .with(LogAndHandleErrorMiddleware)
            .build();

        let server_host = settings
            .api_endpoint
            .host_str()
            .ok_or_else(|| anyhow!("Error getting host from API endpoint"))?;

        let server_did = doh_request(
            &client,
            settings,
            RecordType::TXT,
            &format!("_did.{server_host}"),
        )
        .await?
        .data;

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

    async fn fetch_ucans(&mut self) -> Result<()> {
        let (ucan, proofs) = self.issue_ucan(self.device_did(), IndexingAbility::Fetch)?;

        let request = self
            .server_request(Method::GET, "/api/v0/capabilities")?
            .bearer_auth(ucan.encode()?)
            .header("ucan", encode_ucan_header(&proofs)?);

        let ucans_response: UcansResponse = request.send().await?.json().await?;

        self.ucans.extend(ucans_response.into_unrevoked());

        Ok(())
    }

    async fn create_account(&mut self) -> Result<AccountInfo> {
        let email = inquire::Text::new("What's your email address?").prompt()?;

        self.server_request(Method::POST, "/api/v0/auth/email/verify")?
            .json(&EmailVerifyRequest {
                email: email.clone(),
            })
            .send()
            .await?;

        println!("Successfully requested an email verification code.");

        // TODO verify it's a 6 digit number. Allow retries.
        let code = inquire::Text::new("Please enter the verification code:").prompt()?;

        let (ucan, proofs) = self.issue_ucan(self.device_did(), FissionAbility::AccountCreate)?;

        // TODO Check for availablility. Allow retries.
        let username = inquire::Text::new("Choose a username:").prompt()?;

        let account_creation: AccountCreationResponse = self
            .server_request(Method::POST, "/api/v0/account")?
            .bearer_auth(ucan.encode()?)
            .header("ucan", encode_ucan_header(&proofs)?)
            .header(CONTENT_TYPE, "application/json")
            .json(&AccountCreationRequest {
                email,
                username,
                code: code.trim().to_string(),
            })
            .send()
            .await?
            .json()
            .await?;

        self.ucans.extend(account_creation.ucans);

        Ok(account_creation.account)
    }

    fn find_capabilities(&'s self) -> Result<Vec<(Did, Vec<&'s Ucan>)>> {
        let mut caps = Vec::new();

        tracing::info!(
            num_ucans = self.ucans.len(),
            our_did = ?self.key.did_as_str(),
            "Finding capability chains in local ucan store"
        );

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
                        tracing::debug!(%subject_did, ability = %cap.ability(), "Delegation chain found.");
                        caps.push((subject_did, chain));
                    }
                }
            } else {
                tracing::debug!(
                    ucan = ucan.encode()?,
                    audience = ?ucan.audience(),
                    "Skipping UCAN, not addressed to us"
                );
            }
        }

        Ok(caps)
    }

    async fn find_accounts<'u>(
        &self,
        caps: Vec<(Did, Vec<&'u Ucan>)>,
    ) -> Vec<(AccountInfo, Did, Vec<&'u Ucan>)> {
        let mut accounts = Vec::new();
        for (did, chain) in caps {
            tracing::info!(%did, "Checking if given capability is a valid account");

            let resolve_account = async {
                let ucan =
                    self.issue_ucan_with(did.clone(), FissionAbility::AccountRead, &chain)?;

                let response = self
                    .server_request(Method::GET, &format!("/api/v0/account/{did}"))?
                    .bearer_auth(ucan.encode()?)
                    .header("ucan", encode_ucan_header(&chain)?)
                    .send()
                    .await?;

                let account_info: AccountInfo = response.json().await?;
                tracing::info!(?account_info.username, "Found user");
                Ok::<_, anyhow::Error>(account_info)
            };

            match resolve_account.await {
                Ok(info) => accounts.push((info, did, chain)),
                Err(e) => {
                    tracing::debug!(%e, "Error filtered during find_accounts");
                }
            };
        }
        accounts
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

    async fn rename_account(
        &self,
        did: Did,
        chain: Vec<&Ucan>,
        new_username: String,
    ) -> Result<()> {
        let ucan = self.issue_ucan_with(did, FissionAbility::AccountManage, &chain)?;

        self.server_request(
            Method::PATCH,
            &format!("/api/v0/account/username/{new_username}"),
        )?
        .bearer_auth(ucan.encode()?)
        .header("ucan", encode_ucan_header(&chain)?)
        .send()
        .await?;

        Ok(())
    }

    async fn delete_account(&self, did: Did, chain: Vec<&Ucan>) -> Result<()> {
        let ucan = self.issue_ucan_with(did, FissionAbility::AccountDelete, &chain)?;

        self.server_request(Method::DELETE, "/api/v0/account")?
            .bearer_auth(ucan.encode()?)
            .header("ucan", encode_ucan_header(&chain)?)
            .send()
            .await?;

        Ok(())
    }

    fn server_request(&self, method: Method, path: &str) -> Result<RequestBuilder> {
        let mut url = self.settings.api_endpoint.clone();
        url.set_path(path);
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

async fn doh_request(
    client: &ClientWithMiddleware,
    settings: &Settings,
    record_type: RecordType,
    record: &str,
) -> Result<dns::DohRecordJson> {
    let mut url = settings.api_endpoint.clone();
    url.set_path("dns-query");
    url.set_query(Some(&format!("name={record}&type={record_type}")));

    let response: dns::Response = client
        .get(url)
        .header("Accept", "application/dns-json")
        .send()
        .await?
        .json()
        .await?;

    // Must always be a single answer, since we're asking only a single question
    let answer = response.answer.into_iter().next().ok_or(anyhow!(
        "Missing answer for {record_type} {record} DoH lookup"
    ))?;
    Ok(answer)
}
