//! Models related to capability indexing, specifically the `ucans` and `capabilities` table.

use crate::{
    db::{
        schema::{capabilities, ucans},
        Conn,
    },
    models::revocation::find_revoked_subset,
};
use anyhow::{anyhow, Result};
use chrono::NaiveDateTime;
use diesel::{
    pg::Pg, Associations, ExpressionMethods, Identifiable, Insertable, OptionalExtension, QueryDsl,
    Queryable, Selectable, SelectableHelper,
};
use diesel_async::RunQueryDsl;
use fission_core::{common::UcansResponse, revocation::canonical_cid};
use rs_ucan::{capability::Capability, ucan::Ucan};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
};
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
    pub cid: String,
    /// Token in encoded format
    pub encoded: String,

    /// UCAN `iss` field
    pub issuer: String,
    /// UCAN `aud` field
    pub audience: String,

    /// UCAN `nbf` field
    pub not_before: Option<NaiveDateTime>,
    /// UCAN `exp` field
    pub expires_at: Option<NaiveDateTime>,
}

/// Represents an indexed UCAN that wasn't added to the database yet
#[derive(Debug, Clone, Queryable, Selectable, Insertable, Serialize, Deserialize, ToSchema)]
#[diesel(table_name = ucans)]
#[diesel(check_for_backend(Pg))]
pub struct NewIndexedUcan {
    /// SHA2-256 raw CID of the encoded token
    pub cid: String,
    /// Token in encoded format
    pub encoded: String,

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

/// Represents an indexed capability that hasn't been added to the database yet
#[derive(
    Debug, Clone, Queryable, Selectable, Insertable, Associations, Serialize, Deserialize, ToSchema,
)]
#[diesel(belongs_to(IndexedUcan, foreign_key = ucan_id))]
#[diesel(table_name = capabilities)]
#[diesel(check_for_backend(Pg))]
pub struct NewIndexedCapability {
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

    let new_indexed_ucan = NewIndexedUcan::new(ucan)?;

    let existing_ucan_id: Option<i32> = ucans::table
        .filter(ucans::cid.eq(&new_indexed_ucan.cid))
        .select(ucans::id)
        .get_result::<i32>(conn)
        .await
        .optional()?;

    // We short-circuit if we've stored this before, since then we'd have
    // stored the capabilities as well.
    if let Some(ucan_id) = existing_ucan_id {
        return Ok(IndexedUcan::new(new_indexed_ucan, ucan_id));
    }

    let ucan_id = diesel::insert_into(ucans::table)
        .values(&new_indexed_ucan)
        .returning(ucans::id)
        .get_result(conn)
        .await?;

    let indexed_ucan = IndexedUcan::new(new_indexed_ucan, ucan_id);

    let capabilities = ucan
        .capabilities()
        .map(|cap| NewIndexedCapability::new(cap, ucan_id))
        .collect::<Result<Vec<_>>>()?;

    diesel::insert_into(capabilities::table)
        .values(&capabilities)
        .execute(conn)
        .await?;

    Ok(indexed_ucan)
}

/// Fetch all indexed UCANs that end in a specific audience
pub async fn find_ucans_for_audience(
    audience: String,
    conn: &mut Conn<'_>,
) -> Result<UcansResponse> {
    let mut visited_ids_set = BTreeSet::<i32>::new();
    let mut audience_dids_frontier = BTreeSet::from([audience]);

    loop {
        tracing::debug!(
            visited_ids_set = ?visited_ids_set,
            audience_dids_frontier = ?audience_dids_frontier,
            "UCAN graph search iteration"
        );

        let ids_and_issuers: Vec<(i32, String)> = ucans::table
            .filter(ucans::audience.eq_any(&audience_dids_frontier))
            .filter(ucans::id.ne_all(&visited_ids_set))
            // TODO Also filter by not_before & expires_at. Or should it?
            // TODO only follow edges when they have a common resource/the resource is subsumed
            .select((ucans::id, ucans::issuer))
            .get_results(conn)
            .await?;

        if ids_and_issuers.is_empty() {
            break;
        }

        audience_dids_frontier.clear();

        for (id, issuer) in ids_and_issuers {
            visited_ids_set.insert(id);
            audience_dids_frontier.insert(issuer);
        }
    }

    tracing::debug!(visited_ids_set = ?visited_ids_set, "Finished UCAN graph search");

    let indexed_ucans = ucans::table
        .filter(ucans::id.eq_any(&visited_ids_set))
        .select(IndexedUcan::as_select())
        .get_results(conn)
        .await?;

    let ucans = indexed_ucans
        .into_iter()
        .map(|ucan| {
            let decoded = Ucan::from_str(&ucan.encoded).map_err(|e| anyhow!(e))?;
            Ok((ucan.cid, decoded))
        })
        .collect::<Result<BTreeMap<String, Ucan>>>()?;

    let canonical_cids = ucans.keys().cloned().collect();

    let revoked = find_revoked_subset(canonical_cids, conn).await?;

    Ok(UcansResponse { ucans, revoked })
}

impl NewIndexedUcan {
    fn new(ucan: &Ucan) -> Result<Self> {
        let encoded = ucan.encode()?;
        let issuer = ucan.issuer().to_string();
        let audience = ucan.audience().to_string();

        let not_before = ucan
            .not_before()
            .and_then(|seconds| NaiveDateTime::from_timestamp_millis((seconds * 1000) as i64));

        let expires_at = ucan
            .expires_at()
            .and_then(|seconds| NaiveDateTime::from_timestamp_millis((seconds * 1000) as i64));

        let cid = canonical_cid(ucan)?;

        Ok(Self {
            cid,
            encoded,
            issuer,
            audience,
            not_before,
            expires_at,
        })
    }
}

impl NewIndexedCapability {
    fn new(cap: &Capability, ucan_id: i32) -> Result<Self> {
        let resource = cap.resource().to_string();
        let ability = cap.ability().to_string();
        let caveats = cap.caveat().serialize(serde_json::value::Serializer)?;

        Ok(Self {
            resource,
            ability,
            caveats,
            ucan_id,
        })
    }
}

impl IndexedUcan {
    fn new(new_ucan: NewIndexedUcan, id: i32) -> Self {
        let NewIndexedUcan {
            cid,
            encoded,
            issuer,
            audience,
            not_before,
            expires_at,
        } = new_ucan;
        Self {
            id,
            cid,
            encoded,
            issuer,
            audience,
            not_before,
            expires_at,
        }
    }
}

impl IndexedCapability {
    #[allow(unused)]
    fn new(new_cap: NewIndexedCapability, id: i32) -> Self {
        let NewIndexedCapability {
            resource,
            ability,
            caveats,
            ucan_id,
        } = new_cap;
        Self {
            id,
            resource,
            ability,
            caveats,
            ucan_id,
        }
    }
}
