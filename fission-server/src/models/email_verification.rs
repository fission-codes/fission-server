//! Email Verification Model
use openssl::sha::Sha256;
use serde::Deserialize;
use std::collections::HashMap;
use tracing::log;
use utoipa::ToSchema;
use validator::{Validate, ValidationError};

use anyhow::Result;

use mailgun_rs::{EmailAddress, Mailgun, Message};

use rand::Rng;

use crate::settings::Settings;

/// Generate a code that can be sent to the user.
fn generate_code() -> u32 {
    let mut rng = rand::thread_rng();
    // This is maybe way too little entropy. That said, my bank sends me 5 digit codes. 🤷‍♂️
    rng.gen_range(10000..=99999)
}

/// [Request] Parameters
#[derive(Deserialize, Validate, Clone, Debug, ToSchema)]
pub struct Request {
    /// The email address of the user signing up
    #[validate(email)]
    pub email: String,
    /// The (pre-generated) did of the client application.
    /// Currently only did:key is supported.
    pub did: String,
    #[serde(skip)]
    #[serde(default = "generate_code")]
    code: u32,
    /// The hash of the code, so that it can only be used by the intended recipient.
    /// We only store the hash, not the code itself.
    #[serde(skip_deserializing)]
    pub code_hash: Option<String>,
}

impl Request {
    /// Computes a hash of the code (so that it can only be used by the intended
    /// recipient) and stores it in the struct.
    pub fn compute_code_hash(&mut self) -> Result<()> {
        if self.validate().is_err() {
            log::error!("ERROR: Failed to validate the request.");
            return Err(ValidationError::new("Failed to validate the request.").into());
        }

        let mut hasher = Sha256::new();
        hasher.update(self.email.as_bytes());
        hasher.update(self.did.as_bytes());
        hasher.update(self.code.to_string().as_bytes());
        let result = hasher.finish();
        self.code_hash = Some(hex::encode(result));
        Ok(())
    }

    /// Sends the code to the user
    pub async fn send_code(&self) -> Result<()> {
        if self.code_hash.is_none() {
            log::error!("ERROR: Code hash must be generated before sending code.");
            return Err(
                ValidationError::new("Code hash must be generated before sending code.").into(),
            );
        }

        let delivery_address = EmailAddress::address(&self.email.clone());

        if self.validate().is_err() {
            log::error!("ERROR: Failed to validate the request.");
            return Err(ValidationError::new("Failed to validate the request.").into());
        }

        let server_settings = Settings::load()?;
        let settings = server_settings.mailgun();

        let mut template_vars = HashMap::new();
        template_vars.insert("code".to_string(), self.code.to_string());

        let message = Message {
            to: vec![delivery_address],
            subject: settings.subject.clone(),
            template: settings.template.clone(),
            template_vars,
            ..Default::default()
        };

        print!("{} {}", settings.api_key.clone(), settings.domain.clone());
        let client = Mailgun {
            api_key: settings.api_key.clone(),
            domain: settings.domain.clone(),
            message,
        };

        let sender = EmailAddress::name_address(&settings.from_name, &settings.from_address);

        // The mailgun library doesn't support async, so we have to spawn a blocking task.
        if let Err(e) = tokio::task::spawn_blocking(move || client.send(&sender)).await? {
            log::error!("ERROR: Failed to send the message to the recipient. {}.", e);
            return Err(e)?;
        };

        Ok(())
    }

    // fn generate_code_hash(&self) -> String {
    //     let mut hasher = Sha256::new();
    //     hasher.update(self.email.as_bytes());
    //     hasher.update(self.did.as_bytes());
    //     hasher.update(self.code.to_string().as_bytes());
    //     let result = hasher.finalize();
    //     hex::encode(result)
    // }

    // pub fn to_record(&self) -> Record {
    //     let code_hash = self.generate_code_hash();
    //     Record {
    //         email: self.email.clone(),
    //         did: self.did.clone(),
    //         code_hash,
    //     }
    // }
}

/// The Email Verification [Record] that we store internally
#[derive(Debug)]
pub struct Record {
    /// The email address of the user
    pub email: String,
    /// The did associated with the user's client
    pub did: String,
    /// The hash of the code
    /// We don't store the code itself, only the hash, since it's treated like a
    /// password. We salt the hash with the email and DID.
    ///
    /// We do send the code to the user in plaintext, however.
    pub code_hash: String,
}

// impl Request {
//     /// Create a new instance of [Request]
//     pub fn new(email: String, did: String) -> Self {
//         Self { email, did }
//     }

//     pub fn generate_code_hash(&self) -> String {
//         let mut hasher = Sha256::new();
//         hasher.update(self.email.as_bytes());
//         hasher.update(self.did.as_bytes());
//         let result = hasher.finalize();
//         hex::encode(result)
//     }
// }
