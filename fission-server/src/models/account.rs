//! Fission Account Model

use did_key::{generate, Ed25519KeyPair, Fingerprint};

use chrono::NaiveDateTime;
use diesel::prelude::*;
use serde::{ser::SerializeStruct, Deserialize, Serialize};
use ucan::builder::UcanBuilder;
use utoipa::ToSchema;

use diesel_async::RunQueryDsl;

use crate::{
    crypto::patchedkey::PatchedKeyPair,
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

#[derive(
    Debug, Queryable, Selectable, Insertable, Clone, Identifiable, Associations, Serialize,
)]
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
        did: &String,
    ) -> Result<Self, diesel::result::Error> {
        let new_account = NewAccountRecord {
            did: did.to_string(),
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
        _ucan: Option<ucan::Ucan>,
        username: String,
    ) -> Result<Self, diesel::result::Error> {
        //let account = accounts::dsl::accounts
        accounts::dsl::accounts
            .filter(accounts::username.eq(username))
            .first::<Account>(conn)
            .await

        // FIXME this should actually validate that the UCAN has access, not just that the DID matches
        // if let Ok(account) = account {
        //     if *ucan.issuer().to_string() == account.did {
        //         return Ok(account);
        //     }
        // }

        // Err(diesel::result::Error::NotFound)
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
        conn: &mut Conn<'_>,
        cid: String,
    ) -> Result<NewVolumeRecord, diesel::result::Error> {
        let volume = Volume::new(conn, cid).await?;
        let volume_id = volume.id;

        diesel::update(accounts::dsl::accounts)
            .filter(accounts::id.eq(self.id))
            .set(accounts::volume_id.eq(volume_id))
            .execute(conn)
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
pub struct AccountRequest {
    /// Username associated with the account
    pub username: String,
    /// Email address associated with the account
    pub email: String,
}

impl From<Account> for AccountRequest {
    fn from(account: Account) -> Self {
        Self {
            username: account.username,
            email: account.email,
        }
    }
}

/// Account with Root Authority (UCAN)
#[derive(Clone, Debug)]
pub struct RootAccount {
    /// The Associated Account
    pub account: Account,
    /// A UCAN with Root Authority
    pub ucan: ucan::Ucan,
}

/// Account with Root Authority (UCAN)
impl RootAccount {
    /// Create a new Account with a Root Authority (UCAN)
    pub async fn new(
        conn: &mut Conn<'_>,
        username: String,
        email: String,
        audience_did: &str,
    ) -> Result<Self, anyhow::Error> {
        // FIXME did-key library should zeroize memory https://github.com/decentralized-identity/did-key.rs/issues/40
        // Alt: we should switch to a different crate that does this.
        let ephemeral_key = generate::<Ed25519KeyPair>(None);
        let ephemeral_key = PatchedKeyPair(ephemeral_key);
        let did = format!("did:key:{}", ephemeral_key.0.fingerprint());

        let account = Account::new(conn, username, email, &did).await?;

        let ucan = UcanBuilder::default()
            .issued_by(&ephemeral_key)
            .for_audience(audience_did)
            // QUESTION: How long should these be valid for? This is basically sign-in expiry/duration.
            .with_lifetime(60 * 60 * 24 * 365)
            // Need to implement capabilities here
            // .claiming_capability(capability)
            .build()?
            .sign()
            .await?;

        Ok(Self { ucan, account })
    }
}

impl Serialize for RootAccount {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // I don't know how to convert anyhow::Error to Serde's Error without
        // doing a From<> Trait impl for anyhow::Error, so I'm just going to do
        // it live. We'll just do it live. Also, Quinn is on it and figuring out the correct minimal incantation.
        let encoded_ucan = self.ucan.encode();
        if let Ok(encoded_ucan) = encoded_ucan {
            let mut state = serializer.serialize_struct("RootAccount", 2)?;
            state.serialize_field("account", &self.account)?;
            state.serialize_field("ucan", &encoded_ucan)?;
            state.end()
        } else {
            Err(serde::ser::Error::custom("Failed to encode UCAN"))
        }
    }
}
