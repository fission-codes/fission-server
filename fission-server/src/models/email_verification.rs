//! Email Verification Model
use anyhow::Result;
use async_trait::async_trait;
use chrono::NaiveDateTime;
use diesel::{
    dsl::{now, IntervalDsl},
    pg::Pg,
    ExpressionMethods, Insertable, QueryDsl, Queryable, Selectable, SelectableHelper,
};
use diesel_async::RunQueryDsl;
use mailgun_rs::{EmailAddress, Mailgun, MailgunRegion, Message};
use openssl::sha::Sha256;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::log;
use utoipa::ToSchema;
use validator::{Validate, ValidationError};

use crate::{
    db::{schema::email_verifications, Conn},
    settings,
    traits::VerificationCodeSender,
};

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

/// Email Verification Request
#[derive(Insertable, Debug)]
#[diesel(table_name = email_verifications)]
pub struct NewEmailVerification {
    /// Email address associated with the account
    pub email: String,
    /// The (pre-generated) did of the client application.
    pub did: String,
    /// The hash of the code, so that it can only be used by the intended recipient.
    pub code_hash: String,
}

/// Email Verification Record
#[derive(Debug, Queryable, Selectable, Insertable, Clone)]
#[diesel(table_name = email_verifications)]
#[diesel(check_for_backend(Pg))]
pub struct EmailVerification {
    /// Internal Database Identifier
    pub id: i32,

    /// Inserted at timestamp
    pub inserted_at: NaiveDateTime,
    /// Updated at timestamp
    pub updated_at: NaiveDateTime,

    /// Email address associated with the account
    pub email: String,

    /// The hash of the code, so that it can only be used by the intended recipient.
    /// We only store the hash, not the code itself.
    pub code_hash: String,

    /// The (pre-generated) did of the client application.
    /// Currently only did:key is supported.
    pub did: String,
}

impl EmailVerification {
    /// Create a new instance of [EmailVerification]
    pub async fn new(
        conn: &mut Conn<'_>,
        request: Request,
        did: &str,
    ) -> Result<Self, diesel::result::Error> {
        let new_request = NewEmailVerification {
            email: request.email,
            did: did.to_string(),
            code_hash: request.code_hash.unwrap(),
        };

        tracing::debug!("Creating new email verification request: {:?}", new_request);

        diesel::insert_into(email_verifications::table)
            .values(&new_request)
            .returning(EmailVerification::as_select())
            .get_result(conn)
            .await
    }

    /// Find a token by email, did, and code.
    pub async fn find_token(
        conn: &mut Conn<'_>,
        email: &str,
        verification: &EmailVerificationFacts,
    ) -> Result<Self> {
        let code_hash = hash_code(email, &verification.did, verification.code);

        tracing::debug!(
            "Looking up email verification request for email: {}, did: {}, code: {}",
            email,
            &verification.did,
            verification.code
        );

        Ok(email_verifications::table
            .filter(email_verifications::email.eq(email))
            .filter(email_verifications::did.eq(&verification.did))
            .filter(email_verifications::code_hash.eq(&code_hash))
            .filter(email_verifications::inserted_at.ge(now - 24.hours()))
            .first(conn)
            .await?)
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
    pub fn compute_code_hash(&mut self, did: &str) -> Result<()> {
        if self.validate().is_err() {
            log::error!("ERROR: Failed to validate the request.");
            return Err(ValidationError::new("Failed to validate the request.").into());
        }

        log::debug!(
            "Computing code hash for email: {} did: {} code: {}",
            self.email,
            did,
            self.code
        );

        self.code_hash = Some(hash_code(&self.email, did, self.code));
        Ok(())
    }

    /// Send the verification code in the request
    pub async fn send_code<T>(&self, verification_code_sender: T) -> Result<()>
    where
        T: VerificationCodeSender,
    {
        if self.code_hash.is_none() {
            log::error!("ERROR: Code hash must be generated before sending code.");
            return Err(
                ValidationError::new("Code hash must be generated before sending code.").into(),
            );
        }

        verification_code_sender
            .send_code(&self.email, &self.code.to_string())
            .await
    }
}

/// This stores the information a client has to provide when returning with an
/// email verification code.
///
/// Email verification needs two factors:
/// 1. Access to read emails
/// 2. Access to the keypair on the device that originally created the email verification request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailVerificationFacts {
    /// The verification code
    pub code: u64,
    /// The DID that was originally used to initiate the email verification
    pub did: String,
}
