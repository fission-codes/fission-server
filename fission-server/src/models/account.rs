//! Fission Account Model

use super::capability_indexing::index_ucan;
use crate::{
    db::{
        schema::{accounts, ucans},
        Conn,
    },
    models::volume::{NewVolumeRecord, Volume},
    setups::IpfsDatabase,
};
use anyhow::{bail, Result};
use chrono::NaiveDateTime;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use fission_core::{capabilities::did::Did, ed_did_key::EdDidKey};
use rs_ucan::{
    builder::UcanBuilder,
    capability::Capability,
    semantics::{ability::TopAbility, caveat::EmptyCaveat},
    ucan::Ucan,
};
use serde::{Deserialize, Serialize};
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
    ToSchema,
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
    /// `user_did`
    pub async fn new(
        conn: &mut Conn<'_>,
        username: String,
        email: String,
        user_did: &str,
        server: &EdDidKey,
    ) -> Result<Self> {
        let (ucans, account_did) = Self::issue_root_ucans(server, user_did, conn).await?;
        let account = Account::new(conn, username, email, account_did).await?;

        Ok(Self { ucans, account })
    }

    /// Give an agent access to an existing account.
    /// This is sort-of logging in.
    ///
    /// This will generate another delegation from the server to the
    /// account.
    pub async fn link_agent(
        account: Account,
        agent_did: &str,
        server: &EdDidKey,
        conn: &mut Conn<'_>,
    ) -> Result<Self> {
        let server_ucan: String = ucans::table
            .filter(ucans::issuer.eq(&account.did))
            .filter(ucans::audience.eq(server.did_as_str()))
            .select(ucans::encoded)
            .get_result(conn)
            .await?;

        let server_ucan: Ucan = Ucan::from_str(&server_ucan)?;

        let account_did = account.did.clone();

        let agent_ucan =
            Self::issue_agent_ucan(server, account_did, agent_did, &server_ucan, conn).await?;

        Ok(Self {
            ucans: vec![server_ucan, agent_ucan],
            account,
        })
    }

    async fn issue_root_ucans(
        server: &EdDidKey,
        agent_did: &str,
        conn: &mut Conn<'_>,
    ) -> Result<(Vec<Ucan>, String)> {
        let account = EdDidKey::generate(); // Zeroized on drop

        // Delegate all access to the fission server
        let capability = Capability::new(Did(account.did()), TopAbility, EmptyCaveat);
        let server_ucan: Ucan = UcanBuilder::default()
            .for_audience(server)
            .claiming_capability(capability)
            .sign(&account)?;

        // Persist UCAN in the DB
        index_ucan(&server_ucan, conn).await?;

        // Delegate the account to the agent
        let agent_ucan =
            Self::issue_agent_ucan(server, account.did(), agent_did, &server_ucan, conn).await?;

        Ok((vec![server_ucan, agent_ucan], account.did()))
    }

    async fn issue_agent_ucan(
        server: &EdDidKey,
        account_did: String,
        agent_did: &str,
        server_ucan: &Ucan,
        conn: &mut Conn<'_>,
    ) -> Result<Ucan> {
        // Delegate the account to the agent
        let capability = Capability::new(Did(account_did), TopAbility, EmptyCaveat);
        let agent_ucan: Ucan = UcanBuilder::default()
            .for_audience(agent_did)
            .claiming_capability(capability)
            .witnessed_by(server_ucan, None)
            .sign(server)?;

        index_ucan(&agent_ucan, conn).await?;

        Ok(agent_ucan)
    }
}
