//! Fission Account Model

use std::sync::Arc;
use tokio::sync::Mutex;

use chrono::NaiveDateTime;
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use diesel_async::RunQueryDsl;

use crate::{
    db::{schema::accounts, Conn},
    models::volume::{NewVolumeRecord, Volume},
};

/// New Account Struct (for creating new accounts)
#[derive(Insertable)]
#[diesel(table_name = accounts)]
struct NewAccountRecord {
    did: String,
    username: String,
    email: String,
}

#[derive(Debug, Queryable, Selectable, Insertable, Clone, Identifiable, Associations)]
#[diesel(belongs_to(Volume))]
#[diesel(table_name = accounts)]
/// Fission Account model
pub struct Account {
    /// Internal Database Identifier
    pub id: i32,

    /// Account DID
    pub did: String,

    /// Username associated with the account
    pub username: String,

    /// Email address associated with the account
    pub email: String,

    /// App ID associated with the account
    pub app_id: Option<i32>,

    /// Inserted at timestamp
    pub inserted_at: NaiveDateTime,

    /// Updated at timestamp
    pub updated_at: NaiveDateTime,

    /// Volume ID
    pub volume_id: Option<i32>,
}

impl Account {
    /// Create a new Account. Inserts the account into the database.
    pub async fn new(
        conn: &mut Conn<'_>,
        username: String,
        email: String,
        did: String,
    ) -> Result<Self, diesel::result::Error> {
        let new_account = NewAccountRecord {
            did,
            username,
            email,
        };

        diesel::insert_into(accounts::table)
            .values(&new_account)
            .get_result(conn)
            .await
    }

    /// Find a Fission Account by username, validate that the UCAN has permission to access it
    pub async fn find_by_username(
        conn: &mut Conn<'_>,
        ucan: ucan::Ucan,
        username: String,
    ) -> Result<Self, diesel::result::Error> {
        let account = accounts::dsl::accounts
            .filter(accounts::username.eq(username))
            .first::<Account>(conn)
            .await;

        // FIXME this should actually validate that the UCAN has access, not just that the DID matches
        if let Ok(account) = account {
            if *ucan.issuer().to_string() == account.did {
                return Ok(account);
            }
        }

        Err(diesel::result::Error::NotFound)
    }

    /// Update the controlling DID of a Fission Account
    //
    // Unlike the update_volume_cid method below, this could be done with one SQL query, but
    // for consistency, we're using two; fetch the account and then update it, as separate operations.
    //
    // There's probably an elegant way to do that chaining with Rust and Diesel, but I don't know how
    // to do it and (1) it's not a huge deal performance-wise, and (2) it would be a lot more complex.
    pub async fn update_did(
        &self,
        conn: &mut Conn<'_>,
        new_did: String,
    ) -> Result<Self, diesel::result::Error> {
        // FIXME this needs to account for delegation and check that the correct
        // capabilities have been delegated. Currently we only support using the root did.
        diesel::update(accounts::dsl::accounts)
            .filter(accounts::id.eq(self.id))
            .set(accounts::did.eq(new_did))
            .get_result(conn)
            .await
    }

    /// Get the volume associated with the user's account.
    //
    // Note: this doesn't use a join, but rather a separate query to the volumes table.
    // Possibly not ideal, but it's simple and works.
    pub async fn get_volume(
        &self,
        conn: &mut Conn<'_>,
        // ucan: ucan::Ucan,
        // nb not including the ucan here, because in order to get the account,
        // we've already validated the UCAN. HOWEVER, we should probably validate
        // that the UCAN has access to the volume here.
    ) -> Result<NewVolumeRecord, diesel::result::Error> {
        if let Some(volume_id) = self.volume_id {
            let volume = Volume::find_by_id(conn, volume_id).await?;
            Ok(volume.into())
        } else {
            Err(diesel::result::Error::NotFound)
        }
    }

    /// Create a volume record and update the account to point to it.
    pub async fn set_volume_cid(
        &self,
        conn: Arc<Mutex<Conn<'_>>>,
        cid: String,
    ) -> Result<NewVolumeRecord, diesel::result::Error> {
        let volume = Volume::new(conn.clone(), cid).await?;
        let volume_id = volume.id;

        let mut conn = conn.lock().await;
        diesel::update(accounts::dsl::accounts)
            .filter(accounts::id.eq(self.id))
            .set(accounts::volume_id.eq(volume_id))
            .execute(&mut conn)
            .await?;
        Ok(volume.into())
    }

    /// Update the CID of the user's volume.
    //
    // Note: I'm not extremely stoked about having two SQL queries when we could
    // do it with raw SQL in one, but I'm not sure how to do that with Diesel.
    //
    // It seems complicated.
    //
    // However, both queries are very fast and simple, so it's not a huge deal.
    pub async fn update_volume_cid(
        &self,
        conn: &mut Conn<'_>,
        cid: String,
    ) -> Result<NewVolumeRecord, diesel::result::Error> {
        if let Some(volume_id) = self.volume_id {
            let volume = Volume::find_by_id(conn, volume_id)
                .await?
                .update_cid(conn, cid)
                .await?;
            Ok(volume.into())
        } else {
            // FIXME wrong error type
            Err(diesel::result::Error::NotFound)
        }
    }
}

/// Account Request Struct (for creating new accounts)
#[derive(Deserialize, Serialize, Clone, Debug, ToSchema)]
pub struct NewAccount {
    /// Username associated with the account
    pub username: String,
    /// Email address associated with the account
    pub email: String,
    /// DID associated with the account
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
