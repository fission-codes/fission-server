//! Email Verification Model
use crate::db::{schema::email_verifications, Conn};
use anyhow::Result;
use chrono::NaiveDateTime;
use diesel::{
    dsl::{now, IntervalDsl},
    pg::Pg,
    ExpressionMethods, Insertable, QueryDsl, Queryable, Selectable, SelectableHelper,
};
use diesel_async::RunQueryDsl;
use fission_core::common::EmailVerifyRequest;
use hex::ToHex;
use rand::Rng;

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
        request: &EmailVerifyRequest,
    ) -> Result<Self, diesel::result::Error> {
        let record = NewEmailVerification {
            email: request.email.clone(),
            code: generate_code(),
        };

        tracing::debug!("Creating new email verification record: {:?}", record);

        diesel::insert_into(email_verifications::table)
            .values(&record)
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
