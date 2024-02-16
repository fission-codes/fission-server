//! Main fission-cli command line entry points
use crate::{
    logging::{LogAndHandleErrorMiddleware, LoggingCacheManager},
    paths::config_file,
    responses::AccountAndAuth,
    settings::Settings,
    ucan::{encode_ucan_header, find_delegation_chain},
};
use anyhow::{anyhow, bail, Context, Result};
use car_mirror::{
    cache::InMemoryCache,
    common::stream_car_frames,
    incremental_verification::IncrementalDagVerification,
    messages::{PullRequest, PushResponse},
};
use chrono::Utc;
use clap::{Parser, Subcommand};
use ed25519::pkcs8::{spki::der::pem::LineEnding, DecodePrivateKey, EncodePrivateKey};
use ed25519_dalek::SigningKey;
use fission_core::{
    capabilities::{
        did::Did,
        fission::{FissionAbility, FissionPlugin},
        indexing::IndexingAbility,
    },
    common::{
        Account, AccountCreationRequest, AccountLinkRequest, EmailVerifyRequest, UcansResponse,
    },
    dns,
    ed_did_key::EdDidKey,
    username::{Handle, Username},
};
use futures::stream::TryStreamExt;
use hickory_proto::rr::RecordType;
use http_cache_reqwest::{CACacheManager, Cache, CacheMode, HttpCache, HttpCacheOptions};
use inquire::ui::RenderConfig;
use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;
use reqwest::{header::CONTENT_TYPE, Body, Client, Method, StatusCode};
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware, RequestBuilder};
use rs_ucan::{
    builder::UcanBuilder,
    capability::Capability,
    plugins::Plugin,
    semantics::{ability::Ability, caveat::EmptyCaveat},
    ucan::Ucan,
};
use std::{
    fmt::Debug,
    fs::{create_dir_all, OpenOptions},
    io::{self, Read},
    path::{Path, PathBuf},
    str::FromStr,
};
use tokio::fs::{self, File};
use tokio_util::{compat::FuturesAsyncReadCompatExt, io::StreamReader};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use wnfs::{
    common::{libipld::Cid, BlockStore, MemoryBlockStore, Storable},
    public::{PublicDirectory, PublicNode},
};

#[derive(Debug, Parser)]
#[command(name = "fission")]
#[command(about = "Manage your fission account from the command line")]
pub struct Cli {
    #[arg(long, help = "Path to a .pem file with the secret key for this device")]
    key_file: Option<PathBuf>,
    #[arg(
        long,
        hide = true,
        help = "Provide a seed for an in-memory DID. Used for testing."
    )]
    key_seed: Option<String>,
    #[arg(long, help = "Whether to turn off ansi terminal colors")]
    no_colors: bool,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Account and login management commands
    Account(AccountCmds),
    /// Commands related to managing the account-associated storage
    Volume(VolumeCmds),
    /// Print file paths used by the application (e.g. the path to config)
    Paths,
}

#[derive(Debug, Parser)]
pub struct AccountCmds {
    #[command(subcommand)]
    command: AccountCommands,
}

#[derive(Debug, Subcommand)]
pub enum AccountCommands {
    /// Create a new fission account (even if you already have one)
    Create,
    /// Login to an existing fission account via email verification code
    Login,
    /// List fission accounts that you currently have access on from this device
    List,
    /// Give one of your accounts a new name
    Rename(RenameCommand),
    /// Delete one of your accounts
    Delete(DeleteCommand),
    /// Issue UCANs for given ability
    Issue(IssueAbility),
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

#[derive(Debug, Parser)]
pub struct IssueAbility {
    /// The ability to issue, e.g. "account/info" or "account/manage"
    ability: String,
    /// The lifetime for which the ability should be issued,
    /// use "forever" in case it shouldn't have a time limit
    #[arg(long)]
    lifetime: Option<String>,
}

#[derive(Debug, Parser)]
pub struct VolumeCmds {
    #[command(subcommand)]
    command: VolumeCommands,
}

#[derive(Debug, Subcommand)]
pub enum VolumeCommands {
    /// Publish a directory or file as a volume
    Publish(PublishCommand),
    /// Download a volume to given directory
    Download(DownloadCommand),
}

#[derive(Debug, Parser)]
pub struct PublishCommand {
    /// Path to the directory to publish
    path: PathBuf,
    /// Username of the account to use for uploading.
    /// If not provided, it's assumed you only have access to one account.
    #[arg(long, short = 'u')]
    username: Option<String>,
}

#[derive(Debug, Parser)]
pub struct DownloadCommand {
    /// The domain name of the volume to download. Alternatively can be a CID.
    volume: String,
    /// Path to the directory where to download the volume to
    #[arg(long, short = 'o')]
    output: PathBuf,
}

impl Cli {
    pub async fn run(&self, mut settings: Settings) -> Result<()> {
        let ansi = !self.no_colors;
        setup_tracing(ansi);

        if let Some(key_file) = &self.key_file {
            settings.key_file = key_file.clone();
        }

        match &self.command {
            Commands::Account(account) => {
                let mut state = CliState::load(&settings, self.key_seed.clone(), ansi).await?;
                state.fetch_ucans().await?;

                match &account.command {
                    AccountCommands::Create => {
                        let account = state.create_account().await?;

                        println!("Successfully created your account");

                        tracing::info!(?account, "Created account");
                    }
                    AccountCommands::Login => {
                        let account = state.link_account().await?;

                        println!("Successfully logged in");

                        tracing::info!(?account, "Logged into account");
                    }
                    AccountCommands::List => {
                        let auths = state.find_accounts(state.find_capabilities()?).await;
                        if auths.is_empty() {
                            println!("You don't have access to any accounts yet. Use \"fission-cli account create\" to create a new one.");
                        } else {
                            println!(
                                "Here's a list of accounts you have access to from this device:"
                            );

                            for auth in auths {
                                match &auth.account.username {
                                    Some(username) => {
                                        println!("{}", username.to_unicode());
                                    }
                                    None => {
                                        println!("Anonymous account with DID {}", auth.account.did);
                                    }
                                }
                            }
                        }
                    }
                    AccountCommands::Rename(rename) => {
                        let accounts = state.find_accounts(state.find_capabilities()?).await;

                        let auth = state.pick_account(
                            accounts,
                            &rename.username,
                            "Which account do you want to rename?",
                        )?;
                        let did = Did(auth.account.did.to_string());

                        let new_username = inquire::Text::new("Pick a new username:")
                            .with_render_config(state.render_config)
                            .prompt()?;

                        if new_username.contains('.') {
                            println!(
                                "Looks like you're trying to associate a handle with your account."
                            );
                            println!("Please make sure to have a DNS TXT record for _did.{new_username} with its value set to {did}");
                            println!(
                                "This is needed for our backend to verify that you are the owner of that domain name."
                            );
                            let new_handle = Handle::from_unicode(&new_username)?;

                            inquire::Confirm::new("Have you verified that the DNS record is set?")
                                .with_render_config(state.render_config)
                                .prompt()?;

                            state
                                .add_handle_account(did, &auth.ucans, new_handle)
                                .await?;
                        } else {
                            let new_username = Username::from_unicode(&new_username)?;

                            state.rename_account(did, &auth.ucans, new_username).await?;
                        }
                        println!("Successfully changed your username.");
                    }
                    AccountCommands::Delete(delete) => {
                        let accounts = state.find_accounts(state.find_capabilities()?).await;

                        let auth = state.pick_account(
                            accounts,
                            &delete.username,
                            "Which account do you want to delete?",
                        )?;

                        state
                            .delete_account(Did(auth.account.did.to_string()), &auth.ucans)
                            .await?;

                        println!("Successfully deleted your account.");
                    }
                    AccountCommands::Issue(ability) => {
                        let lifetime = match ability.lifetime.as_deref() {
                            Some("forever") => None,
                            None => Some(360),
                            Some(num) => Some(num.parse().context("Parsing lifetime parameter")?),
                        };

                        let ability = FissionPlugin::try_handle_ability(
                            &FissionPlugin,
                            &Did(String::new()),
                            &ability.ability,
                        )
                        .context("Parsing ability")?
                        .ok_or(anyhow!("Failed to parse ability"))?;

                        let accounts = state.find_accounts(state.find_capabilities()?).await;

                        let auth = state.pick_account(
                            accounts,
                            &None,
                            "Which account do you want to issue an ability from?",
                        )?;

                        let ucan = state.issue_ucan_with(
                            Did(auth.account.did.clone()),
                            ability,
                            Some(lifetime),
                            &auth.ucans,
                        )?;

                        println!("Authorization: Bearer {}", ucan.encode()?);
                        println!();
                        println!(
                            "ucans: {}",
                            auth.ucans
                                .iter()
                                .map(|ucan| ucan.encode().map_err(|e| anyhow!(e)))
                                .collect::<Result<Vec<_>>>()?
                                .join(",")
                        );
                    }
                }
            }
            Commands::Volume(volume) => {
                let mut state = CliState::load(&settings, self.key_seed.clone(), ansi).await?;
                state.fetch_ucans().await?;

                match &volume.command {
                    VolumeCommands::Publish(publish) => {
                        let accounts = state.find_accounts(state.find_capabilities()?).await;

                        let auth = state.pick_account(
                            accounts,
                            &publish.username,
                            "Which account do you want to use?",
                        )?;
                        let did = Did(auth.account.did.to_string());

                        let store = &MemoryBlockStore::new();
                        let cache = &InMemoryCache::new(100_000);

                        let source = &publish.path;
                        if !source.exists() {
                            bail!("Can't publish path, it doesn't exist: {}", source.display());
                        }

                        let cid = if source.is_file() {
                            let filename = source
                                .file_name()
                                .expect("If the source is a file, it should have a filename")
                                .to_string_lossy()
                                .to_string();
                            let mut directory = PublicDirectory::new_rc(Utc::now());
                            directory
                                .write(&[filename], std::fs::read(source)?, Utc::now(), store)
                                .await?;
                            directory.store(store).await?
                        } else {
                            // TODO(matheus23)
                            bail!("Uploading directories is not yet implemented.");
                        };

                        state
                            .volume_put(did, &auth.ucans, cid, store, cache)
                            .await?;
                    }
                    VolumeCommands::Download(download) => {
                        let store = &MemoryBlockStore::new();
                        let cache = &InMemoryCache::new(100_000);

                        if download.output.is_file() {
                            bail!(
                                "Can't write to {}: Expected a directory, but got a file.",
                                download.output.to_string_lossy()
                            );
                        }

                        fs::create_dir_all(&download.output).await?;

                        let cid = if let Ok(cid) = Cid::from_str(&download.volume) {
                            println!("Interpreting the input as a CID");
                            cid
                        } else {
                            let record = doh_request(
                                &state.client,
                                &settings,
                                RecordType::TXT,
                                &format!("_dnslink.{}", download.volume),
                            )
                            .await?;

                            let cid = record
                                .data
                                .strip_prefix("dnslink=/ipfs/")
                                .ok_or(anyhow!("Failed parsing dnslink record: {}", record.data))?;

                            Cid::from_str(cid)?
                        };

                        state.volume_get(cid, store, cache).await?;
                        let directory = PublicDirectory::load(&cid, store).await?;
                        export_dir_to(download.output.clone(), &directory, store).await?;
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
    pub(crate) render_config: RenderConfig,
    pub(crate) key: EdDidKey,
    pub(crate) client: ClientWithMiddleware,
    pub(crate) server_did: String,
    pub(crate) ucans: Vec<Ucan>,
}

impl<'s> CliState<'s> {
    async fn load(
        settings: &'s Settings,
        key_seed: Option<String>,
        colors: bool,
    ) -> Result<CliState<'s>> {
        let key = load_key(settings, key_seed)?;
        tracing::info!(%key, "Generated or loaded DID");

        let render_config = if colors {
            RenderConfig::default_colored()
        } else {
            RenderConfig::empty()
        };

        let client = ClientBuilder::new(Client::new())
            .with(LogAndHandleErrorMiddleware)
            .with(Cache(HttpCache {
                mode: CacheMode::Default,
                manager: LoggingCacheManager::new(CACacheManager {
                    path: settings.http_cache_dir.clone(),
                }),
                options: HttpCacheOptions::default(),
            }))
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
            render_config,
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
            .header("ucans", encode_ucan_header(&proofs)?);

        let ucans_response: UcansResponse = request.send().await?.json().await?;

        self.ucans.extend(ucans_response.into_unrevoked());

        Ok(())
    }

    async fn request_email_verification(&self) -> Result<(String, String)> {
        let email = inquire::Text::new("What's your email address?")
            .with_render_config(self.render_config)
            .prompt()?;
        tracing::info!(email, "Email entered");

        self.server_request(Method::POST, "/api/v0/auth/email/verify")?
            .json(&EmailVerifyRequest {
                email: email.clone(),
            })
            .send()
            .await?;

        println!("Successfully requested an email verification code.");

        // TODO verify it's a 6 digit number. Allow retries.
        let code = inquire::Text::new("Please enter the verification code:")
            .with_render_config(self.render_config)
            .prompt()?;

        Ok((email, code))
    }

    async fn create_account(&mut self) -> Result<Account> {
        let (email, code) = self.request_email_verification().await?;

        let (ucan, proofs) = self.issue_ucan(self.device_did(), FissionAbility::AccountCreate)?;

        // TODO Check for availablility. Allow retries.
        let username = inquire::Text::new("Choose a username:")
            .with_render_config(self.render_config)
            .prompt()?;
        let username = Username::from_unicode(&username)?;

        let response: AccountAndAuth = self
            .server_request(Method::POST, "/api/v0/account")?
            .bearer_auth(ucan.encode()?)
            .header("ucans", encode_ucan_header(&proofs)?)
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

        self.ucans.extend(response.ucans);

        Ok(response.account)
    }

    async fn link_account(&mut self) -> Result<Account> {
        let username = inquire::Text::new("What's your username?")
            .with_render_config(self.render_config)
            .prompt()?;

        let account_did = doh_request(
            &self.client,
            self.settings,
            RecordType::TXT,
            &format!("_did.{username}"),
        )
        .await
        .context("Looking up user DID")?
        .data;

        let (_, code) = self.request_email_verification().await?;

        let (ucan, proofs) = self.issue_ucan(self.device_did(), FissionAbility::AccountLink)?;

        let response: AccountAndAuth = self
            .server_request(Method::POST, &format!("/api/v0/account/{account_did}/link"))?
            .bearer_auth(ucan.encode()?)
            .header("ucans", encode_ucan_header(&proofs)?)
            .header(CONTENT_TYPE, "application/json")
            .json(&AccountLinkRequest {
                code: code.trim().to_string(),
            })
            .send()
            .await?
            .json()
            .await?;

        self.ucans.extend(response.ucans);

        Ok(response.account)
    }

    fn find_capabilities(&self) -> Result<Vec<(Did, Vec<Ucan>)>> {
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

    async fn find_accounts(&self, caps: Vec<(Did, Vec<Ucan>)>) -> Vec<AccountAndAuth> {
        let mut auths = Vec::new();
        for (did, chain) in caps {
            tracing::info!(%did, "Checking if given capability is a valid account");

            let resolve_account = async {
                let ucan =
                    self.issue_ucan_with(did.clone(), FissionAbility::AccountInfo, None, &chain)?;

                let account: Account = self
                    .server_request(Method::GET, "/api/v0/account")?
                    .bearer_auth(ucan.encode()?)
                    .header("ucans", encode_ucan_header(&chain)?)
                    .send()
                    .await?
                    .json()
                    .await?;

                tracing::info!(?account.username, "Found user");

                Ok::<_, anyhow::Error>(AccountAndAuth {
                    account,
                    ucans: chain,
                })
            };

            match resolve_account.await {
                Ok(auth) => auths.push(auth),
                Err(e) => {
                    tracing::debug!(%e, "Error filtered during find_accounts");
                }
            };
        }
        auths
    }

    fn pick_account(
        &self,
        accounts: Vec<AccountAndAuth>,
        user_choice: &Option<String>,
        prompt: &str,
    ) -> Result<AccountAndAuth> {
        Ok(match user_choice {
            Some(username) => accounts
                .into_iter()
                .find(|auth| auth.account.username.as_ref().map(Handle::as_str) == Some(username))
                .ok_or_else(|| anyhow!("Couldn't find access to an account with this username."))?,
            None => {
                if accounts.len() > 1 {
                    let account_names = accounts
                        .iter()
                        .map(|auth| {
                            auth.account
                                .username
                                .as_ref()
                                .map_or(auth.account.did.to_string(), |handle| handle.to_unicode())
                        })
                        .collect();

                    let account_name = inquire::Select::new(prompt, account_names)
                        .with_render_config(self.render_config)
                        .prompt()?;

                    accounts
                        .into_iter()
                        .find(|auth| {
                            auth.account
                                .username
                                .as_ref()
                                .map_or(auth.account.did.to_string(), |handle| handle.to_unicode())
                                == account_name
                        })
                        .ok_or_else(|| anyhow!("Something went wrong. Couldn't select account."))?
                } else {
                    accounts
                        .into_iter()
                        .next()
                        .ok_or_else(|| anyhow!("You don't seem to have access to an account yet. Try runing fission-cli account create."))?
                }
            }
        })
    }

    async fn rename_account(&self, did: Did, chain: &[Ucan], new_username: Username) -> Result<()> {
        let ucan = self.issue_ucan_with(did, FissionAbility::AccountManage, None, chain)?;

        self.server_request(
            Method::PATCH,
            &format!("/api/v0/account/username/{new_username}"),
        )?
        .bearer_auth(ucan.encode()?)
        .header("ucans", encode_ucan_header(chain)?)
        .send()
        .await?;

        Ok(())
    }

    async fn add_handle_account(&self, did: Did, chain: &[Ucan], handle: Handle) -> Result<()> {
        let ucan = self.issue_ucan_with(did, FissionAbility::AccountManage, None, chain)?;

        self.server_request(Method::PATCH, &format!("/api/v0/account/handle/{handle}"))?
            .bearer_auth(ucan.encode()?)
            .header("ucans", encode_ucan_header(chain)?)
            .send()
            .await?;

        Ok(())
    }

    async fn delete_account(&self, did: Did, chain: &[Ucan]) -> Result<()> {
        let ucan = self.issue_ucan_with(did, FissionAbility::AccountDelete, None, chain)?;

        self.server_request(Method::DELETE, "/api/v0/account")?
            .bearer_auth(ucan.encode()?)
            .header("ucans", encode_ucan_header(chain)?)
            .send()
            .await?;

        Ok(())
    }

    async fn volume_put(
        &self,
        did: Did,
        chain: &[Ucan],
        cid: Cid,
        store: &MemoryBlockStore,
        cache: &InMemoryCache,
    ) -> Result<()> {
        // We use a custom client, because we need to skip caching requests,
        // as our caching middleware from http-cache will fail on reqwest body streams.
        let client = ClientBuilder::new(Client::new())
            .with(LogAndHandleErrorMiddleware)
            .build();

        let mut upload_url = self.settings.api_endpoint.clone();
        upload_url.set_path(&format!("/api/v0/volume/cid/{cid}"));

        let mut push_state = None;

        loop {
            let block_stream = car_mirror::common::block_send_block_stream(
                cid,
                push_state,
                store.clone(),
                cache.clone(),
            )
            .await?;
            let car_stream = stream_car_frames(block_stream).await?;
            let reqwest_stream = Body::wrap_stream(car_stream);

            let ucan =
                self.issue_ucan_with(did.clone(), FissionAbility::AccountManage, None, chain)?;

            let answer = client
                .put(upload_url.clone())
                .bearer_auth(ucan.encode()?)
                .header("ucans", encode_ucan_header(chain)?)
                .body(reqwest_stream)
                .send()
                .await?;

            match answer.status() {
                StatusCode::OK => {
                    println!("Successfully updated");
                    return Ok(());
                }
                StatusCode::ACCEPTED => {
                    // We need to continue.
                }
                other => {
                    bail!(
                        "Unexpected status code: {other}, err: {}",
                        answer.text().await?
                    );
                }
            }

            let response: PushResponse = answer.json().await?;
            push_state = Some(response.into());
        }
    }

    async fn volume_get(
        &self,
        cid: Cid,
        store: &MemoryBlockStore,
        cache: &InMemoryCache,
    ) -> Result<()> {
        // We use a custom client, because we need to skip caching requests,
        // as our caching middleware from http-cache will fail on reqwest body streams.
        let client = ClientBuilder::new(Client::new())
            .with(LogAndHandleErrorMiddleware)
            .build();

        let mut download_url = self.settings.api_endpoint.clone();
        download_url.set_path(&format!("/api/v0/volume/cid/{cid}"));

        let config = &car_mirror::common::Config::default();

        let mut pull_request: PullRequest = IncrementalDagVerification::new([cid], &store, &cache)
            .await?
            .into_receiver_state(config.bloom_fpr)
            .into();

        while !pull_request.indicates_finished() {
            let answer = client
                .get(download_url.clone())
                .json(&pull_request)
                .send()
                .await?
                .error_for_status()?;

            let stream = StreamReader::new(answer.bytes_stream().map_err(io::Error::other));

            pull_request =
                car_mirror::common::block_receive_car_stream(cid, stream, config, store, cache)
                    .await?
                    .into();
        }

        println!("Finished downloading");

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
    ) -> Result<(Ucan, Vec<Ucan>)> {
        let Some(chain) =
            find_delegation_chain(&subject_did, &ability, self.key.did_as_str(), &self.ucans)
        else {
            bail!("Couldn't find proof for ability {ability} on subject {subject_did}");
        };

        let ucan = self.issue_ucan_with(subject_did, ability, None, &chain)?;

        Ok((ucan, chain))
    }

    fn issue_ucan_with(
        &self,
        subject_did: Did,
        ability: impl Ability,
        lifetime: Option<Option<u64>>,
        chain: &[Ucan],
    ) -> Result<Ucan> {
        let mut builder = UcanBuilder::default()
            .for_audience(&self.server_did)
            .claiming_capability(Capability::new(subject_did, ability, EmptyCaveat));

        if let Some(lifetime) = lifetime.unwrap_or(Some(360)) {
            builder = builder.with_lifetime(lifetime);
        }

        if let Some(first) = chain.first() {
            builder = builder.witnessed_by(first, None);
        }

        Ok(builder.sign(&self.key)?)
    }
}

fn load_key(settings: &Settings, key_seed: Option<String>) -> Result<EdDidKey> {
    if let Some(key_seed) = key_seed {
        tracing::info!(?key_seed, "Generating key from seed");
        return Ok(EdDidKey::new(SigningKey::generate(
            &mut ChaCha12Rng::from_seed(blake3::hash(key_seed.as_bytes()).into()),
        )));
    }

    let key_path = &settings.key_file;

    if let Some(dir) = key_path.parent() {
        create_dir_all(dir)?;
    }

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
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

fn setup_tracing(ansi: bool) {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(ansi)
                .with_writer(std::io::stderr),
        )
        .with(EnvFilter::from_default_env())
        .init();
}

#[async_recursion::async_recursion]
async fn export_dir_to(
    path: PathBuf,
    directory: &PublicDirectory,
    store: &impl BlockStore,
) -> Result<()> {
    for (name, _) in directory.ls(&[], store).await? {
        let entry_path = Path::new(&name);
        if !entry_path.is_relative() {
            eprintln!("Skipping directory entry \"{name}\", as it can't be parsed as relative path segment");
            continue;
        }

        let node = directory
            .get_node(&[name.clone()], store)
            .await?
            .expect("Node must be there, we just got it from ls");
        match node {
            PublicNode::File(file) => {
                let mut fs_file = File::create(path.join(entry_path)).await?;
                let mut stream = file.stream_content(0, store).await?.compat();
                tokio::io::copy(&mut stream, &mut fs_file).await?;
            }
            PublicNode::Dir(dir) => export_dir_to(path.join(entry_path), dir, store).await?,
        }
    }

    Ok(())
}
