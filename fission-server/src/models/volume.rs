//! Volume model

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;

use chrono::NaiveDateTime;
use diesel::prelude::*;
use utoipa::ToSchema;

use diesel_async::RunQueryDsl;

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

impl From<Volume> for NewVolumeRecord {
    fn from(volume: Volume) -> Self {
        Self { cid: volume.cid }
    }
}

impl Volume {
    /// Create a new Volume. Inserts the volume into the database.
    pub async fn new(
        conn: Arc<Mutex<Conn<'_>>>,
        cid: String,
    ) -> Result<Self, diesel::result::Error> {
        let mut conn = conn.lock().await;
        let new_volume = NewVolumeRecord { cid };

        diesel::insert_into(volumes::table)
            .values(new_volume)
            .get_result(&mut conn)
            .await
    }

    /// Find a volume by its primary key
    pub async fn find_by_id(
        conn: Arc<Mutex<Conn<'_>>>,
        id: i32,
    ) -> Result<Self, diesel::result::Error> {
        let mut conn = conn.lock().await;

        volumes::table
            .filter(volumes::id.eq(id))
            .get_result(&mut conn)
            .await
    }

    /// Update a volume by its CID
    pub async fn update_cid(
        &self,
        conn: Arc<Mutex<Conn<'_>>>,
        cid: String,
    ) -> Result<Self, diesel::result::Error> {
        let mut conn = conn.lock().await;

        diesel::update(volumes::table)
            .filter(volumes::id.eq(self.id))
            .set(volumes::cid.eq(cid))
            .get_result(&mut conn)
            .await
    }
}
