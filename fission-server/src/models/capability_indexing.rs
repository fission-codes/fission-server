//! Models related to capability indexing, specifically the `ucans` and `capabilities` table.

use crate::{
    db::{
        schema::{capabilities, ucans},
        Conn,
    },
    models::revocation::find_revoked_subset,
};
use anyhow::{anyhow, Result};
use chrono::{DateTime, NaiveDateTime};
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
    #[schema(value_type = Option<String>)]
    pub not_before: Option<NaiveDateTime>,
    /// UCAN `exp` field
    #[schema(value_type = Option<String>)]
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
    #[schema(value_type = Option<String>)]
    pub not_before: Option<NaiveDateTime>,
    /// UCAN `exp` field
    #[schema(value_type = Option<String>)]
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
    tracing::debug!(audience, "Doing initial lookup of UCANs matching audience");

    let ids_issuers_resources: Vec<(i32, String, String)> = ucans::table
        .inner_join(capabilities::table)
        .filter(ucans::audience.eq(&audience))
        .select((ucans::id, ucans::issuer, capabilities::resource))
        .get_results(conn)
        .await?;

    let ids = ids_issuers_resources.iter().map(|(id, _, _)| id).cloned();
    let issuers = ids_issuers_resources.iter().map(|(_, iss, _)| iss).cloned();

    let mut visited_ids_set = BTreeSet::<i32>::from_iter(ids);
    let mut audience_dids_frontier = BTreeSet::from_iter(issuers);

    let resources = ids_issuers_resources
        .into_iter()
        .map(|(_, _, res)| res)
        .collect::<Vec<_>>();

    tracing::debug!(
        ?resources,
        "Looking for resources (not yet looking for subsumtions)"
    );

    loop {
        tracing::debug!(
            visited_ids_set = ?visited_ids_set,
            audience_dids_frontier = ?audience_dids_frontier,
            "UCAN graph search iteration"
        );

        let ids_and_issuers: Vec<(i32, String)> = ucans::table
            .inner_join(capabilities::table)
            .filter(ucans::audience.eq_any(&audience_dids_frontier))
            .filter(ucans::id.ne_all(&visited_ids_set))
            // TODO: Support subsumtion of resources/capabilities
            .filter(capabilities::resource.eq_any(&resources))
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
            .and_then(|seconds| DateTime::from_timestamp_millis((seconds * 1000) as i64))
            .map(|dt| dt.naive_utc());

        let expires_at = ucan
            .expires_at()
            .and_then(|seconds| DateTime::from_timestamp_millis((seconds * 1000) as i64))
            .map(|dt| dt.naive_utc());

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::test_context::TestContext;
    use fission_core::{
        capabilities::{did::Did, fission::FissionAbility},
        ed_did_key::EdDidKey,
    };
    use rs_ucan::{builder::UcanBuilder, semantics::caveat::EmptyCaveat};
    use testresult::TestResult;

    #[test_log::test(tokio::test)]
    async fn test_find_ucan_by_audience_single() -> TestResult {
        let ctx = &TestContext::new().await?;
        let conn = &mut ctx.get_db_conn().await?;

        let issuer = EdDidKey::generate();
        let audience = EdDidKey::generate();

        let ucan: Ucan = UcanBuilder::default()
            .for_audience(&audience)
            .claiming_capability(Capability::new(
                Did(issuer.did()),
                FissionAbility::AccountManage,
                EmptyCaveat,
            ))
            .sign(&issuer)?;

        index_ucan(&ucan, conn).await?;

        let response = find_ucans_for_audience(audience.did(), conn).await?;

        assert_eq!(response.ucans.len(), 1);

        let response_ucan = response.ucans.first_key_value().unwrap().1;

        assert_eq!(response_ucan.to_cid(None)?, ucan.to_cid(None)?);

        Ok(())
    }

    #[test_log::test(tokio::test)]
    async fn test_find_ucan_by_audience_transitive() -> TestResult {
        let ctx = &TestContext::new().await?;
        let conn = &mut ctx.get_db_conn().await?;

        let alice = EdDidKey::generate();
        let bob = EdDidKey::generate();
        let carol = EdDidKey::generate();

        let cap = Capability::new(Did(alice.did()), FissionAbility::AccountManage, EmptyCaveat);

        let root_ucan: Ucan = UcanBuilder::default()
            .for_audience(&bob)
            .claiming_capability(cap.clone())
            .sign(&alice)?;

        let ucan: Ucan = UcanBuilder::default()
            .for_audience(&carol)
            .claiming_capability(cap)
            .sign(&bob)?;

        index_ucan(&root_ucan, conn).await?;
        index_ucan(&ucan, conn).await?;

        let response_bob = find_ucans_for_audience(bob.did(), conn).await?;
        let response_carol = find_ucans_for_audience(carol.did(), conn).await?;

        // Bob still only gets one UCAN
        assert_eq!(response_bob.ucans.len(), 1);
        // Carol gets the whole chain
        assert_eq!(response_carol.ucans.len(), 2);

        let ucan_cids = response_carol.ucans.into_keys().collect::<BTreeSet<_>>();
        let expected_cids = BTreeSet::from([
            root_ucan.to_cid(None)?.to_string(),
            ucan.to_cid(None)?.to_string(),
        ]);

        assert_eq!(ucan_cids, expected_cids);

        Ok(())
    }

    #[test_log::test(tokio::test)]
    async fn test_find_ucan_by_audience_only_matching_resource() -> TestResult {
        let ctx = &TestContext::new().await?;
        let conn = &mut ctx.get_db_conn().await?;

        let alice = EdDidKey::generate();
        let bob = EdDidKey::generate();
        let carol = EdDidKey::generate();

        let cap_a = Capability::new(Did(alice.did()), FissionAbility::AccountManage, EmptyCaveat);
        let cap_b = Capability::new(Did(bob.did()), FissionAbility::AccountManage, EmptyCaveat);

        let ucan_a: Ucan = UcanBuilder::default()
            .for_audience(&bob)
            .claiming_capability(cap_a)
            .sign(&alice)?;

        let ucan_b: Ucan = UcanBuilder::default()
            .for_audience(&carol)
            .claiming_capability(cap_b) // Different capability!
            .sign(&bob)?;

        index_ucan(&ucan_a, conn).await?;
        index_ucan(&ucan_b, conn).await?;

        let response_bob = find_ucans_for_audience(bob.did(), conn).await?;
        let response_carol = find_ucans_for_audience(carol.did(), conn).await?;

        // Bob still only gets one UCAN
        assert_eq!(response_bob.ucans.len(), 1);
        // Carol gets the whole chain
        assert_eq!(response_carol.ucans.len(), 1);

        let ucan_cids = response_carol.ucans.into_keys().collect::<BTreeSet<_>>();
        let expected_cids = BTreeSet::from([ucan_b.to_cid(None)?.to_string()]);

        // Carol doesn't get the UCAN that's not matching the same resource
        assert_eq!(ucan_cids, expected_cids);

        Ok(())
    }
}
