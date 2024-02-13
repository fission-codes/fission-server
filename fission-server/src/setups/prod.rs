//! Production server setup code

use crate::{
    // middleware::{client::metrics::Metrics, logging::Logger},
    settings,
    setups::{IpfsDatabase, ServerSetup, VerificationCodeSender},
};
use anyhow::{anyhow, bail, Context as _, Result};
use async_trait::async_trait;
use bytes::Bytes;
use cid::Cid;
use mailgun_rs::{EmailAddress, Mailgun, MailgunRegion, Message};
use reqwest::multipart::{Form, Part};
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware, RequestBuilder};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    str::FromStr,
};
use tracing::log;
use url::Url;
use wnfs::common::BlockStoreError;

/// Production implementatoin of `ServerSetup`.
/// Actually calls out to other HTTP services configured in `settings.toml`.
#[derive(Clone, Debug, Default)]
pub struct ProdSetup;

impl ServerSetup for ProdSetup {
    type IpfsDatabase = IpfsHttpApiDatabase;
    type VerificationCodeSender = EmailVerificationCodeSender;
}

/// An implementation of `IpfsDatabase` which connects to a locally-running
/// IPFS kubo node.
#[derive(Clone, Debug)]
pub struct IpfsHttpApiDatabase {
    client: ClientWithMiddleware,
    codecs: BTreeMap<u64, String>,
    mhtypes: BTreeMap<u64, String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct KuboRpcError {
    #[allow(dead_code)] // false positive, we're using it through the debug print implementation
    message: String,
    code: u64,
    #[allow(dead_code)]
    r#type: String,
}

impl IpfsHttpApiDatabase {
    /// Connect to a local kubo RPC instance over localhost:5001.
    /// Configures a bunch of standard middelwares for tracing, metrics and more
    /// on the reqwest client.
    /// Fails if it can't connect & run some RPCs.
    pub async fn new() -> Result<Self> {
        Self::new_with(
            ClientBuilder::new(Default::default())
                // .with(Logger)
                // .with(Metrics {
                //     name: "Local Kubo RPC".to_string(),
                // })
                .build(),
        )
        .await
    }

    /// Connect to a local kubo RPC instance over localhost:5001 with given client.
    /// Fails if it can't connect & run some RPCs.
    pub async fn new_with(client: ClientWithMiddleware) -> Result<Self> {
        #[derive(Serialize, Deserialize)]
        #[serde(rename_all = "PascalCase")]
        struct CodeName {
            code: u64,
            name: String,
        }

        tracing::debug!("Finding supported codecs in connected Kubo instance");

        let codec_list = Self::client_rpc(&client, "/api/v0/cid/codecs", None)
            .send()
            .await?
            .json::<Vec<CodeName>>()
            .await?;

        let hash_list = Self::client_rpc(&client, "/api/v0/cid/hashes", None)
            .send()
            .await?
            .json::<Vec<CodeName>>()
            .await?;

        let codecs =
            BTreeMap::from_iter(codec_list.into_iter().map(|codec| (codec.code, codec.name)));
        let mhtypes = BTreeMap::from_iter(hash_list.into_iter().map(|hash| (hash.code, hash.name)));

        Ok(Self {
            client,
            codecs,
            mhtypes,
        })
    }

    /// Build up a raw RPC
    pub fn rpc(&self, function: &str, query: Option<&str>) -> RequestBuilder {
        Self::client_rpc(&self.client, function, query)
    }

    fn client_rpc(
        client: &ClientWithMiddleware,
        function: &str,
        query: Option<&str>,
    ) -> RequestBuilder {
        tracing::info!(function, ?query, "Calling kubo RPC");
        let mut url =
            Url::parse("http://localhost:5001").expect("should be able to parse hardcoded URL");
        url.set_path(function);
        url.set_query(query);
        client.post(url)
    }
}

impl IpfsDatabase for IpfsHttpApiDatabase {
    async fn pin_add(&self, cid: &str, recursive: bool) -> Result<()> {
        self.rpc(
            "/api/v0/pin/add",
            Some(&format!("arg=/ipfs/{cid}&recursive={recursive}")),
        )
        .send()
        .await?;
        Ok(())
    }

    async fn pin_update(&self, cid_before: &str, cid_after: &str, unpin: bool) -> Result<()> {
        self.rpc(
            "/api/v0/pin/update",
            Some(&format!(
                "arg=/ipfs/{cid_before}&arg=/ipfs/{cid_after}&unpin={unpin}"
            )),
        )
        .send()
        .await?;
        Ok(())
    }

    async fn block_put(&self, cid_codec: u64, mhtype: u64, data: Vec<u8>) -> Result<Cid> {
        let cid_codec = self.codecs.get(&cid_codec).ok_or_else(|| {
            anyhow!("Codec not supported in connected kubo instance: {cid_codec:#06x}")
        })?;

        let mhtype = self.mhtypes.get(&mhtype).ok_or_else(|| {
            anyhow!("Multihash type not supported in connected kubo instance: {mhtype:#06x}")
        })?;

        let form = Form::new().part("block", Part::bytes(data));

        #[derive(Deserialize, Serialize)]
        #[serde(rename_all = "PascalCase")]
        struct Response {
            key: String,
            size: u64,
        }

        let response = self
            .rpc(
                "/api/v0/block/put",
                Some(&format!("cid-codec={cid_codec}&mhtype={mhtype}")),
            )
            .multipart(form)
            .send()
            .await?;
        let response = response.json::<Response>().await?;

        let cid = Cid::from_str(&response.key).context("Trying to parse block/put response CID")?;

        Ok(cid)
    }

    async fn block_get(&self, cid: &str) -> Result<Bytes> {
        let response = self
            .rpc(
                "/api/v0/block/get",
                Some(&format!("arg={cid}&offline=true")),
            )
            .send()
            .await?;

        if response.status().is_server_error() {
            let err = response.json::<KuboRpcError>().await?;
            if err.code == 0 {
                bail!(BlockStoreError::CIDNotFound(Cid::from_str(cid)?));
            } else {
                bail!("Kubo RPC failed: {err:?}");
            }
        }

        Ok(response.bytes().await?)
    }
}

#[derive(Debug, Clone)]
/// Sends verification codes over email
pub struct EmailVerificationCodeSender {
    settings: settings::Mailgun,
}

impl EmailVerificationCodeSender {
    /// Create a new EmailVerificationCodeSender
    pub fn new(settings: settings::Mailgun) -> Self {
        Self { settings }
    }

    fn sender(&self) -> EmailAddress {
        EmailAddress::name_address(&self.settings.from_name, &self.settings.from_address)
    }

    fn subject(&self) -> &str {
        self.settings.subject.as_str()
    }

    fn template(&self) -> &str {
        self.settings.template.as_str()
    }

    fn api_key(&self) -> &str {
        self.settings.api_key.as_str()
    }

    fn domain(&self) -> &str {
        self.settings.domain.as_str()
    }

    fn message(&self, email: &str, code: &str) -> Message {
        let delivery_address = EmailAddress::address(email);
        let template_vars = HashMap::from_iter([("code".to_string(), code.to_string())]);

        Message {
            to: vec![delivery_address],
            subject: self.subject().to_string(),
            template: self.template().to_string(),
            template_vars,
            ..Default::default()
        }
    }
}

#[async_trait]
impl VerificationCodeSender for EmailVerificationCodeSender {
    /// Sends the code to the user
    async fn send_code(&self, email: &str, code: &str) -> Result<()> {
        let message = self.message(email, code);

        log::debug!(
            "Sending verification email:\nTo: {}\nSubject: {}\nTemplate: {}\nTemplate Vars: {:?}",
            email,
            message.subject,
            message.template,
            message.template_vars
        );

        let client = Mailgun {
            message,
            api_key: self.api_key().to_string(),
            domain: self.domain().to_string(),
        };

        client.async_send(MailgunRegion::US, &self.sender()).await?;

        Ok(())
    }
}
