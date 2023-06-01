#![allow(missing_docs)]
use chrono::NaiveDateTime;
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use diesel_async::RunQueryDsl;

use crate::db::Conn;

use crate::db::schema::accounts;

/// New Account Struct (for creating new accounts)
#[derive(Insertable)]
#[diesel(table_name = accounts)]
struct NewAccountRecord {
    did: String,
    username: String,
    email: String,
}

#[derive(Debug, Queryable, Selectable, Insertable, Clone)]
#[diesel(table_name = accounts)]
/// Fission Account model
pub struct Account {
    pub id: i32,

    /// Account DID
    pub did: String,

    /// Username associated with the account
    pub username: String,

    /// Email address associated with the account
    pub email: String,

    // pub app_id: i32,
    pub inserted_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

impl Account {
    pub async fn new(mut conn: Conn<'_>, username: String, email: String, did: String) -> Self {
        let new_account = NewAccountRecord {
            did,
            username,
            email,
        };

        diesel::insert_into(accounts::table)
            .values(&new_account)
            .get_result(&mut conn)
            .await
            .expect("Error saving new account")
    }

    pub async fn find_by_username(
        mut conn: Conn<'_>,
        username: String,
    ) -> Result<Self, diesel::result::Error> {
        accounts::dsl::accounts
            .filter(accounts::username.eq(username))
            .first(&mut conn)
            .await
    }
}

/// Account Request Struct (for creating new accounts)
#[derive(Deserialize, Serialize, Clone, Debug, ToSchema)]
pub struct NewAccount {
    pub username: String,
    pub email: String,
    pub did: String,
}

impl From<Account> for NewAccount {
    fn from(account: Account) -> Self {
        Self {
            username: account.username,
            email: account.email,
            did: account.did,
        }
    }
}
