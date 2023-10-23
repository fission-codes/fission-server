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
use hex::ToHex;
use mailgun_rs::{EmailAddress, Mailgun, MailgunRegion, Message};
use rand::Rng;
use serde::Deserialize;
use std::collections::HashMap;
use tracing::log;
use utoipa::ToSchema;
use validator::Validate;

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
    /// The verification code
    pub code: String,
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

    /// The verification code
    pub code: String,
}

impl EmailVerification {
    /// Create a new instance of [EmailVerification]
    pub async fn new(
        conn: &mut Conn<'_>,
        request: &Request,
    ) -> Result<Self, diesel::result::Error> {
        let new_request = NewEmailVerification {
            email: request.email.clone(),
            code: generate_code(),
        };

        tracing::debug!("Creating new email verification request: {:?}", new_request);

        diesel::insert_into(email_verifications::table)
            .values(&new_request)
            .returning(EmailVerification::as_select())
            .get_result(conn)
            .await
    }

    /// Find a token by email, did, and code.
    pub async fn find_token(conn: &mut Conn<'_>, email: &str, code: &str) -> Result<Self> {
        tracing::debug!(
            email = email,
            code = code,
            "Looking up email verification request",
        );

        Ok(email_verifications::table
            .filter(email_verifications::email.eq(email))
            .filter(email_verifications::code.eq(code))
            .filter(email_verifications::inserted_at.ge(now - 24.hours()))
            .first(conn)
            .await?)
    }

    /// *Use* a token, making it impossible for it to be used again
    pub async fn consume_token(self, conn: &mut Conn<'_>) -> Result<()> {
        tracing::debug!(token = ?self, "Consuming verification token");

        diesel::delete(email_verifications::table.filter(email_verifications::id.eq(&self.id)))
            .execute(conn)
            .await?;

        Ok(())
    }
}

/// Generate a code that can be sent to the user.
fn generate_code() -> String {
    let mut rng = rand::thread_rng();
    // This is maybe way too little entropy. That said, my bank sends me 5 digit codes. 🤷‍♂️
    let code = rng.gen_range(0..=99999);
    // 0-pad the 6-digit code:
    format!("{code:0>6}")
}

/// Compute a hash given email and verification code.
pub fn hash_code(email: &str, code: u64) -> String {
    blake3::derive_key(
        "fission server 2023-23-10 email verification codes",
        &[email.as_bytes(), &code.to_le_bytes()].concat(),
    )
    .encode_hex()
}

/// [Request] Parameters
#[derive(Deserialize, Validate, Clone, Debug, ToSchema)]
pub struct Request {
    /// The email address of the user signing up
    #[validate(email)]
    pub email: String,
}
