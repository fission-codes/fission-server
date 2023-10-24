//! Models related to capability indexing, specifically the `ucans` and `capabilities` table.

use crate::db::{
    schema::{capabilities, ucans},
    Conn,
};
use anyhow::Result;
use chrono::NaiveDateTime;
use cid::{
    multihash::{Code, MultihashDigest},
    Cid,
};
use diesel::{
    pg::Pg, Associations, ExpressionMethods, Identifiable, Insertable, OptionalExtension, QueryDsl,
    Queryable, Selectable,
};
use diesel_async::RunQueryDsl;
use rs_ucan::{capability::Capability, ucan::Ucan};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;

/// Represents an indexed UCAN in the database
#[derive(
    Debug, Clone, Queryable, Selectable, Insertable, Identifiable, Serialize, Deserialize, ToSchema,
)]
#[diesel(table_name = ucans)]
#[diesel(check_for_backend(Pg))]
pub struct IndexedUcan {
    /// Internal DB id
    pub id: i32,

    /// SHA2-256 raw CID of the encoded token
    pub cid: Vec<u8>,
    /// Token in encoded format
    pub encoded: Vec<u8>,

    /// UCAN `iss` field
    pub issuer: String,
    /// UCAN `aud` field
    pub audience: String,

    /// UCAN `nbf` field
    pub not_before: Option<NaiveDateTime>,
    /// UCAN `exp` field
    pub expires_at: Option<NaiveDateTime>,
}

/// Represents a database row of an indexed capability
#[derive(
    Debug,
    Clone,
    Queryable,
    Selectable,
    Insertable,
    Identifiable,
    Associations,
    Serialize,
    Deserialize,
    ToSchema,
)]
#[diesel(belongs_to(IndexedUcan, foreign_key = ucan_id))]
#[diesel(table_name = capabilities)]
#[diesel(check_for_backend(Pg))]
pub struct IndexedCapability {
    /// Internal DB id
    pub id: i32,

    /// Capability resource. For our purposes this will always be a DID.
    pub resource: String,
    /// Capability's ability
    pub ability: String,

    /// Any caveats. 'No caveats' would be `[{}]`
    pub caveats: Value,

    /// DB id of the UCAN that this capability is contained in
    pub ucan_id: i32,
}

/// Index a UCAN in the database.
/// Should be idempotent.
pub async fn index_ucan(ucan: &Ucan, conn: &mut Conn<'_>) -> Result<IndexedUcan> {
    use crate::db::schema::*;

    // TODO only index UCANs & their capabilities, if they've been proven!

    let mut indexed_ucan = IndexedUcan::new(ucan)?;

    let existing_ucan_id: Option<i32> = ucans::table
        .filter(ucans::dsl::cid.eq(&indexed_ucan.cid))
        .select(ucans::dsl::id)
        .get_result::<i32>(conn)
        .await
        .optional()?;

    // We short-circuit if we've stored this before
    if let Some(ucan_id) = existing_ucan_id {
        indexed_ucan.id = ucan_id;
        return Ok(indexed_ucan);
    }

    let ucan_id = diesel::insert_into(ucans::table)
        .values(&indexed_ucan)
        .returning(ucans::dsl::id)
        .get_result(conn)
        .await?;

    indexed_ucan.id = ucan_id;

    let capabilities = ucan
        .capabilities()
        .map(|cap| IndexedCapability::new(cap, ucan_id))
        .collect::<Result<Vec<_>>>()?;

    diesel::insert_into(capabilities::table)
        .values(&capabilities)
        .execute(conn)
        .await?;

    Ok(indexed_ucan)
}

impl IndexedUcan {
    fn new(ucan: &Ucan) -> Result<Self> {
        let encoded = ucan.encode()?.as_bytes().to_vec();
        let issuer = ucan.issuer().to_string();
        let audience = ucan.audience().to_string();

        let not_before = ucan
            .not_before()
            .and_then(|seconds| NaiveDateTime::from_timestamp_millis((seconds * 1000) as i64));

        let expires_at = ucan
            .expires_at()
            .and_then(|seconds| NaiveDateTime::from_timestamp_millis((seconds * 1000) as i64));

        let hash = Code::Sha2_256.digest(&encoded);
        // 0x55 is the raw codec
        let cid = Cid::new_v1(0x55, hash).to_bytes();

        Ok(Self {
            id: 0,
            cid,
            encoded,
            issuer,
            audience,
            not_before,
            expires_at,
        })
    }
}

impl IndexedCapability {
    fn new(cap: &Capability, ucan_id: i32) -> Result<Self> {
        let resource = cap.resource().to_string();
        let ability = cap.ability().to_string();
        let caveats = cap.caveat().serialize(serde_json::value::Serializer)?;

        Ok(Self {
            id: 0,
            resource,
            ability,
            caveats,
            ucan_id,
        })
    }
}
