//! DNS Request Handler

use crate::{
    db::{self, Pool},
    models::account::Account,
};
use anyhow::Result;
use async_trait::async_trait;
use std::{borrow::Borrow, sync::Arc};
use trust_dns_server::{
    authority::{
        AuthLookup, Authority, LookupError, LookupOptions, LookupRecords, MessageRequest,
        UpdateResult, ZoneType,
    },
    client::rr::LowerName,
    proto::{
        op::ResponseCode,
        rr::{rdata::TXT, RData, Record, RecordSet, RecordType},
    },
    resolver::{error::ResolveError, Name},
    server::RequestInfo,
};

/// DNS Request Handler
#[derive(Debug)]
pub struct DBBackedAuthority {
    db_pool: Pool,
    origin: LowerName,
}

/// serial field for this server's primary zone DNS records
pub const SERIAL: u32 = 2023000701;

impl DBBackedAuthority {
    /// Create a new database backed authority
    pub fn new(db_pool: Pool, origin: LowerName) -> Self {
        DBBackedAuthority { db_pool, origin }
    }

    async fn db_lookup_user_did(&self, username: String) -> Result<String> {
        let conn = &mut db::connect(&self.db_pool).await?;
        let account = Account::find_by_username(conn, username).await?;
        Ok(account.did)
    }
}

#[async_trait]
impl Authority for DBBackedAuthority {
    type Lookup = AuthLookup;

    fn zone_type(&self) -> ZoneType {
        ZoneType::Primary
    }

    fn is_axfr_allowed(&self) -> bool {
        false
    }

    async fn update(&self, _update: &MessageRequest) -> UpdateResult<bool> {
        Err(ResponseCode::NotImp)
    }

    fn origin(&self) -> &LowerName {
        &self.origin
    }

    async fn lookup(
        &self,
        name: &LowerName,
        _query_type: RecordType,
        lookup_options: LookupOptions,
    ) -> Result<Self::Lookup, LookupError> {
        tracing::debug!(?name, "Trying DB-based DNS lookup");

        let name: &Name = name.borrow();
        let mut name_parts = name.iter();

        match name_parts.next() {
            // Serve requests for e.g. _did.alice.fission.name
            Some(b"_did") => {
                let Some(user_bytes) = name_parts.next() else {
                    return Ok(AuthLookup::Empty);
                };

                let base = Name::from_labels(name_parts)
                    .map_err(|e| LookupError::ResolveError(ResolveError::from(e)))?;

                // base needs to be fission.name, if the request was _did.alice.fission.name
                if base != self.origin().clone().into() {
                    return Ok(AuthLookup::Empty);
                }

                let username = String::from_utf8(user_bytes.to_vec()).map_err(|e| {
                    LookupError::ResolveError(
                        format!("Failed decoding non-utf8 subdomain segment: {e}").into(),
                    )
                })?;

                tracing::info!(%name, %username, "Looking up DID record");

                let account_did = match self.db_lookup_user_did(username).await {
                    Ok(account_did) => account_did,
                    Err(err) => {
                        tracing::debug!(?err, "Account lookup failed during _did DNS entry lookup");
                        return Ok(AuthLookup::Empty);
                    }
                };

                Ok(AuthLookup::answers(
                    LookupRecords::new(lookup_options, Arc::new(did_record_set(name, account_did))),
                    None,
                ))
            }
            Some(b"_dnslink") => {
                tracing::warn!(?name, "DNSLink lookup not yet implemented. Ignoring");

                Ok(AuthLookup::Empty)
            }
            _ => Ok(AuthLookup::Empty),
        }
    }

    async fn search(
        &self,
        request_info: RequestInfo<'_>,
        lookup_options: LookupOptions,
    ) -> Result<Self::Lookup, LookupError> {
        tracing::debug!(query = ?request_info.query, "DNS query running against DB.");

        let lookup_name = request_info.query.name();
        let record_type: RecordType = request_info.query.query_type();

        // TODO match record_type, support SOA record type?
        // We may not need to support it though. It's possible it just gets picked up
        // by other "Authority" implementations in the "Catalog". E.g. putting
        // SOA records into a zone file.
        if !matches!(record_type, RecordType::TXT) {
            tracing::debug!(
                %record_type,
                "Aborting query: only TXT record type supported."
            );

            return Ok(AuthLookup::Empty);
        }

        self.lookup(lookup_name, record_type, lookup_options).await
    }

    async fn get_nsec_records(
        &self,
        _name: &LowerName,
        _lookup_options: LookupOptions,
    ) -> Result<Self::Lookup, LookupError> {
        Ok(AuthLookup::Empty)
    }
}

/// Create a DID DNS entry represented as a RecordSet
pub(crate) fn did_record_set(name: &Name, did: String) -> RecordSet {
    let record = Record::from_rdata(
        name.clone(),
        60 * 60, // 60 * 60 seconds = 1 hour
        RData::TXT(TXT::new(vec![did])),
    );
    record_set(name, RecordType::TXT, SERIAL, record)
}

/// Create a record set with a single record inside
pub(crate) fn record_set(
    name: &Name,
    record_type: RecordType,
    serial: u32,
    record: Record,
) -> RecordSet {
    let mut record_set = RecordSet::new(name, record_type, serial);
    record_set.insert(record, SERIAL);
    record_set
}
