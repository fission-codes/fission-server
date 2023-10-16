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
use fission_core::{capabilities::fission::FissionResource, ed_did_key::EdDidKey};
use rs_ucan::{
    builder::UcanBuilder,
    capability::Capability,
    plugins::ucan::UcanResource,
    semantics::{ability::TopAbility, caveat::EmptyCaveat},
    ucan::Ucan,
};
use serde::{Deserialize, Serialize};
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
    /// UCANs that give root access
    pub ucans: Vec<Ucan>,
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
        user_did: &str,
        server: &EdDidKey,
    ) -> Result<Self, anyhow::Error> {
        let (ucans, root_did) = Self::issue_root_ucans(server, user_did).await?;
        let account = Account::new(conn, username, email, &root_did).await?;

        Ok(Self { ucans, account })
    }

    async fn issue_root_ucans(
        server: &EdDidKey,
        user_did: &str,
    ) -> Result<(Vec<Ucan>, String), anyhow::Error> {
        let account = EdDidKey::generate(); // Zeroized on drop

        let capability = Capability::new(UcanResource::AllProvable, TopAbility, EmptyCaveat);

        // Delegate all access to the fission server
        let server_ucan: Ucan = UcanBuilder::default()
            .issued_by(&account)
            .for_audience(server)
            .claiming_capability(capability)
            .sign(&account)?;

        // Delegate the account to the user
        let capability =
            Capability::new(FissionResource::Did(account.did()), TopAbility, EmptyCaveat);

        let user_ucan: Ucan = UcanBuilder::default()
            .issued_by(server)
            .for_audience(user_did)
            .claiming_capability(capability)
            .sign(server)?;

        Ok((vec![server_ucan, user_ucan], account.did()))
    }
}
