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

use crate::{db::Conn, settings::Settings};

use chrono::NaiveDateTime;
use diesel::prelude::*;

use diesel_async::RunQueryDsl;

use crate::db::schema::email_verifications;

#[derive(Insertable, Debug)]
#[diesel(table_name = email_verifications)]
pub struct NewEmailVerification {
    pub email: String,
    pub did: String,
    pub code_hash: String,
}

#[derive(Debug, Queryable, Selectable, Insertable, Clone)]
#[diesel(table_name = email_verifications)]
pub struct EmailVerification {
    pub id: i32,

    pub inserted_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,

    /// Email address associated with the account
    pub email: String,

    /// The (pre-generated) did of the client application.
    /// Currently only did:key is supported.
    pub did: String,

    /// The hash of the code, so that it can only be used by the intended recipient.
    /// We only store the hash, not the code itself.
    pub code_hash: String,
}

impl EmailVerification {
    /// Create a new instance of [EmailVerification]
    pub async fn new(mut conn: Conn<'_>, request: Request) -> Result<Self, diesel::result::Error> {
        let new_request = NewEmailVerification {
            email: request.email,
            did: request.did,
            code_hash: request.code_hash.unwrap(),
        };

        log::info!("Creating new email verification: {:?}", new_request);

        diesel::insert_into(email_verifications::table)
            .values(&new_request)
            .get_result(&mut conn)
            .await
    }

    pub async fn find_token(mut conn: Conn<'_>, email: &str, did: &str, code: u64) -> Result<Self> {
        let code_hash = hash_code(email, did, code);

        let result = email_verifications::dsl::email_verifications
            .filter(email_verifications::email.eq(email))
            .filter(email_verifications::did.eq(did))
            .filter(email_verifications::code_hash.eq(&code_hash))
            .first(&mut conn)
            .await?;

        Ok(result)
    }
}

/// Generate a code that can be sent to the user.
fn generate_code() -> u64 {
    let mut rng = rand::thread_rng();
    // This is maybe way too little entropy. That said, my bank sends me 5 digit codes. 🤷‍♂️
    rng.gen_range(10000..=99999)
}

/// Compute a hash given email, did, and verification code.
pub fn hash_code(email: &str, did: &str, code: u64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(email.as_bytes());
    hasher.update(did.as_bytes());
    hasher.update(code.to_string().as_bytes());
    let result = hasher.finish();
    hex::encode(result)
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
    code: u64,
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

        self.code_hash = Some(hash_code(&self.email, &self.did, self.code));
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
}
