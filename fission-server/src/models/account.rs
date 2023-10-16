//! Fission Account Model

use crate::{
    db::{schema::accounts, Conn},
    models::volume::{NewVolumeRecord, Volume},
    traits::IpfsDatabase,
};
use anyhow::{bail, Result};
use chrono::NaiveDateTime;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use fission_core::ed_did_key::EdDidKey;
use rs_ucan::{
    builder::UcanBuilder,
    capability::Capability,
    plugins::ucan::UcanResource,
    semantics::{ability::TopAbility, caveat::EmptyCaveat},
    ucan::Ucan,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::str::FromStr;
use utoipa::ToSchema;

/// New Account Struct (for creating new accounts)
#[derive(Insertable)]
#[diesel(table_name = accounts)]
struct NewAccountRecord {
    did: String,
    username: String,
    email: String,
}

#[derive(
    Debug,
    Queryable,
    Selectable,
    Insertable,
    Clone,
    Identifiable,
    Associations,
    Serialize,
    Deserialize,
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
    pub username: Option<String>,

    /// Email address associated with the account
    pub email: Option<String>,

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
        did: &str,
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
    pub async fn find_by_username<U: AsRef<str>>(
        conn: &mut Conn<'_>,
        username: U,
    ) -> Result<Self, diesel::result::Error> {
        let username = username.as_ref();
        //let account = accounts::dsl::accounts
        accounts::dsl::accounts
            .filter(accounts::username.eq(username))
            .first::<Account>(conn)
            .await
    }

    /// Get the volume associated with the user's account.
    //
    // Note: this doesn't use a join, but rather a separate query to the volumes table.
    // Possibly not ideal, but it's simple and works.
    pub async fn get_volume(&self, conn: &mut Conn<'_>) -> Result<Option<NewVolumeRecord>> {
        if let Some(volume_id) = self.volume_id {
            let volume = Volume::find_by_id(conn, volume_id).await?;
            Ok(Some(volume.into()))
        } else {
            Ok(None)
        }
    }

    /// Create a volume record and update the account to point to it.
    pub async fn set_volume_cid(
        &self,
        conn: &mut Conn<'_>,
        cid: &str,
        ipfs_db: &impl IpfsDatabase,
    ) -> Result<NewVolumeRecord> {
        ipfs_db.pin_add(cid, true).await?;

        let volume = Volume::new(conn, cid).await?;

        diesel::update(accounts::dsl::accounts)
            .filter(accounts::id.eq(self.id))
            .set(accounts::volume_id.eq(volume.id))
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
        cid: &str,
        ipfs_db: &impl IpfsDatabase,
    ) -> Result<NewVolumeRecord> {
        if let Some(volume_id) = self.volume_id {
            let volume = Volume::find_by_id(conn, volume_id)
                .await?
                .update_cid(conn, cid, ipfs_db)
                .await?;
            Ok(volume.into())
        } else {
            // FIXME wrong error type
            bail!("No volume associated with account")
        }
    }
}

/// Account with Root Authority (UCAN)
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct RootAccount {
    /// The Associated Account
    pub account: Account,
    /// A UCAN with Root Authority
    #[serde(serialize_with = "encode_ucan")]
    #[serde(deserialize_with = "decode_ucan")]
    pub ucan: Ucan,
}

/// Serialize a UCAN to a string
fn encode_ucan<S>(ucan: &Ucan, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let encoded_ucan = ucan.encode();
    if let Ok(encoded_ucan) = encoded_ucan {
        serializer.serialize_str(&encoded_ucan)
    } else {
        Err(serde::ser::Error::custom("Failed to encode UCAN"))
    }
}

fn decode_ucan<'de, D>(value: D) -> Result<Ucan, D::Error>
where
    D: Deserializer<'de>,
{
    Ucan::from_str(&String::deserialize(value)?)
        .map_err(|e| serde::de::Error::custom(format!("Failed to decode ucan: {e}")))
}

/// Account with Root Authority
impl RootAccount {
    /// Create a new Account with a Root Authority
    ///
    /// This creates an account and generates a keypair that has top-level
    /// authority over the account. The private key is immediately discarded,
    /// and authority is delegated via a UCAN to the DID provided in
    /// `audience_did`
    pub async fn new(
        conn: &mut Conn<'_>,
        username: String,
        email: String,
        audience_did: &str,
    ) -> Result<Self, anyhow::Error> {
        let ucan = Self::issue_root_ucan(audience_did).await?;
        let account = Account::new(conn, username, email, ucan.issuer()).await?;

        Ok(Self { ucan, account })
    }

    async fn issue_root_ucan(audience_did: &str) -> Result<Ucan, anyhow::Error> {
        let issuer = EdDidKey::generate();

        let capability = Capability::new(UcanResource::AllProvable, TopAbility, EmptyCaveat {});

        let ucan: Ucan = UcanBuilder::default()
            .issued_by(&issuer)
            .for_audience(audience_did)
            .claiming_capability(capability)
            .sign(&issuer)?;

        drop(issuer); // just to be explicit: The key material is zeroized here
        Ok(ucan)
    }
}
