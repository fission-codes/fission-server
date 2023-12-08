//! Production server setup code

use crate::setups::IpfsDatabase;
use crate::setups::ServerSetup;
use crate::{settings, setups::VerificationCodeSender};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use ipfs_api_backend_hyper::IpfsApi;
use mailgun_rs::{EmailAddress, Mailgun, MailgunRegion, Message};
use std::collections::HashMap;
use tracing::log;

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
#[derive(Clone, Default)]
pub struct IpfsHttpApiDatabase(ipfs_api::IpfsClient);

impl std::fmt::Debug for IpfsHttpApiDatabase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("IpfsHttpApiDatabase").finish()
    }
}

#[async_trait]
impl IpfsDatabase for IpfsHttpApiDatabase {
    async fn pin_add(&self, cid: &str, recursive: bool) -> Result<()> {
        self.0
            .pin_add(cid, recursive)
            .await
            .map_err(|e| anyhow!("Failed to pin CID: {e}"))?;
        Ok(())
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
