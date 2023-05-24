#![allow(missing_docs)]
use chrono::NaiveDateTime;
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Debug, Queryable)]
/// Fission Account model
pub struct Account {
    pub id: i32,
    pub app_id: i32,

    pub inserted_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,

    /// Account DID
    pub did: String,

    /// Email address associated with the account
    pub email: String,

    /// Username associated with the account
    pub username: String,
}

/// New Account Struct (for creating new accounts)
#[derive(Deserialize, Serialize, Clone, Debug, ToSchema)]
pub struct NewAccount {
    pub username: String,
    pub email: String,
    pub did: String,
}

impl NewAccount {
    /// Create a new instance of [Account]
    pub fn new(username: String, email: String, did: String) -> Self {
        Self {
            username,
            email,
            did,
        }
    }
}
