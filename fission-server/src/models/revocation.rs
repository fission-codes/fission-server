//! Defines UCAN revocation models.

use crate::db::{schema::revocations, Conn};
use anyhow::Result;
use diesel::{
    associations::Identifiable, deserialize::Queryable, pg::Pg, prelude::Insertable,
    ExpressionMethods, QueryDsl, Selectable,
};
use diesel_async::RunQueryDsl;
use fission_core::revocation::Revocation;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use utoipa::ToSchema;

/// Represents a revocation record in the database
#[derive(
    Debug, Clone, Queryable, Selectable, Insertable, Identifiable, Serialize, Deserialize, ToSchema,
)]
#[diesel(table_name = revocations)]
#[diesel(check_for_backend(Pg))]
pub struct RevocationRecord {
    /// Internal DB id
    pub id: i32,

    /// SHA2-256 raw CID of the encoded UCAN
    pub cid: String,
    /// Issuer of the revocation
    pub iss: String,
    /// The revocation signature
    pub challenge: String,
}

/// Represents a revocation that wasn't added to the database yet
#[derive(Debug, Clone, Queryable, Selectable, Insertable, Serialize, Deserialize, ToSchema)]
#[diesel(table_name = revocations)]
#[diesel(check_for_backend(Pg))]
pub struct NewRevocationRecord {
    /// SHA2-256 raw CID of the encoded UCAN
    pub cid: String,
    /// Issuer of the revocation
    pub iss: String,
    /// The revocation signature
    pub challenge: String,
}

impl NewRevocationRecord {
    /// Turn a fission-core revocation into a new revocation record for the DB
    pub fn new(
        Revocation {
            revoke,
            iss,
            challenge,
        }: Revocation,
    ) -> Self {
        Self {
            cid: revoke,
            iss,
            challenge,
        }
    }

    /// Insert this revocation record into the DB and return the stored revocation record.
    pub async fn insert(self, conn: &mut Conn<'_>) -> Result<RevocationRecord> {
        let id = diesel::insert_into(revocations::table)
            .values(&self)
            .returning(revocations::id)
            .get_result(conn)
            .await?;

        let Self {
            cid,
            iss,
            challenge,
        } = self;

        Ok(RevocationRecord {
            cid,
            iss,
            challenge,
            id,
        })
    }
}

/// From a list of canonical CIDs, find the subset that is revoked
pub async fn find_revoked_subset(
    canonical_cids: BTreeSet<String>,
    conn: &mut Conn<'_>,
) -> Result<BTreeSet<String>> {
    let revoked_cids = revocations::table
        .filter(revocations::cid.eq_any(canonical_cids))
        .select(revocations::cid)
        .get_results(conn)
        .await?;

    // Convert into set
    Ok(revoked_cids.into_iter().collect())
}
