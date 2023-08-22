//! Volume model

use serde::{Deserialize, Serialize};

use chrono::NaiveDateTime;
use diesel::prelude::*;
use tracing::log;
use utoipa::ToSchema;

use diesel_async::RunQueryDsl;

use ipfs_api::IpfsApi;

use crate::db::{schema::volumes, Conn};

#[derive(Debug, Queryable, Insertable, Clone, Identifiable, Selectable, ToSchema)]
#[diesel(table_name = volumes)]
/// App model
pub struct Volume {
    /// Internal Database Identifier
    pub id: i32,

    /// Inserted at timestamp
    pub inserted_at: NaiveDateTime,
    /// Updated at timestamp
    pub updated_at: NaiveDateTime,

    /// CID of the Storage Volume
    pub cid: String,
}

#[derive(Deserialize, Serialize, Clone, Insertable, Debug, ToSchema)]
#[diesel(table_name = volumes)]
/// New Volume Struct (for creating new volumes)
pub struct NewVolumeRecord {
    /// Content ID of the volume
    pub cid: String,
}

impl Default for NewVolumeRecord {
    /// Return the null volume.
    fn default() -> Self {
        Self {
            cid: "".to_string(),
        }
    }
}

impl From<Volume> for NewVolumeRecord {
    fn from(volume: Volume) -> Self {
        Self { cid: volume.cid }
    }
}

impl Volume {
    /// Create a new Volume. Inserts the volume into the database.
    pub async fn new(conn: &mut Conn<'_>, cid: &str) -> Result<Self, diesel::result::Error> {
        let new_volume = NewVolumeRecord {
            cid: cid.to_string(),
        };

        diesel::insert_into(volumes::table)
            .values(new_volume)
            .get_result(conn)
            .await
    }

    /// Find a volume by its primary key
    pub async fn find_by_id(conn: &mut Conn<'_>, id: i32) -> Result<Self, diesel::result::Error> {
        volumes::table
            .filter(volumes::id.eq(id))
            .get_result(conn)
            .await
    }

    /// Update a volume by its CID
    pub async fn update_cid(
        &self,
        conn: &mut Conn<'_>,
        cid: &str,
    ) -> Result<Self, diesel::result::Error> {
        let ipfs = ipfs_api::IpfsClient::default();

        let result = ipfs.pin_add(cid, true).await;

        if result.is_err() {
            log::debug!("Error communicating with IPFS: {:?}", result);
            // FIXME: Use better error
            return Err(diesel::result::Error::NotFound);
        }

        diesel::update(volumes::table)
            .filter(volumes::id.eq(self.id))
            .set(volumes::cid.eq(cid))
            .get_result(conn)
            .await
    }
}
