//! DNS Request Handler

use crate::{
    db::{self, Pool},
    models::account::AccountRecord,
};
use anyhow::Result;
use async_trait::async_trait;
use diesel_async::{scoped_futures::ScopedFutureExt, AsyncConnection};
use hickory_server::{
    authority::{
        AuthLookup, Authority, LookupError, LookupOptions, LookupRecords, MessageRequest,
        UpdateResult, ZoneType,
    },
    proto::{
        op::ResponseCode,
        rr::{
            rdata::{SOA, TXT},
            LowerName, RData, Record, RecordSet, RecordType,
        },
    },
    resolver::{error::ResolveError, Name},
    server::RequestInfo,
};
use std::{borrow::Borrow, sync::Arc};

/// DNS Request Handler for user DIDs of the form `{_did,_dnslink}.<username>.<server origin>`
#[derive(Debug)]
pub struct UserRecordsAuthority {
    db_pool: Pool,
    origin: LowerName,
    default_soa: SOA,
    default_ttl: u32,
    dnslink_ttl: u32,
}

impl UserRecordsAuthority {
    /// Create a new database backed authority
    pub fn new(
        db_pool: Pool,
        origin: LowerName,
        default_soa: SOA,
        default_ttl: u32,
        dnslink_ttl: u32,
    ) -> Self {
        UserRecordsAuthority {
            db_pool,
            origin,
            default_soa,
            default_ttl,
            dnslink_ttl,
        }
    }

    async fn db_lookup_user_did(&self, username: String) -> Result<String> {
        let conn = &mut db::connect(&self.db_pool).await?;
        let account = AccountRecord::find_by_username(conn, username).await?;
        Ok(account.did)
    }

    async fn db_lookup_user_dnslink(&self, username: String) -> Result<Option<String>> {
        let conn = &mut db::connect(&self.db_pool).await?;
        conn.transaction(|conn| {
            async move {
                let account = AccountRecord::find_by_username(conn, username).await?;
                Ok(account
                    .get_volume(conn)
                    .await?
                    .map(|volume_record| format!("dnslink=/ipfs/{}", volume_record.cid)))
            }
            .scope_boxed()
        })
        .await
    }
}

#[async_trait]
impl Authority for UserRecordsAuthority {
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
        query_type: RecordType,
        lookup_options: LookupOptions,
    ) -> Result<Self::Lookup, LookupError> {
        if !matches!(query_type, RecordType::TXT) {
            tracing::debug!(
                ?query_type,
                "Aborting DNS lookup on user DIDs, only TXT supported."
            );
            return Ok(AuthLookup::Empty);
        }

        tracing::debug!(?name, "Starting user DID DNS lookup");

        let name: &Name = name.borrow();
        let mut name_parts = name.iter();
        let first = name_parts.next();

        let Some(user_bytes) = name_parts.next() else {
            return Ok(AuthLookup::Empty);
        };

        let base = Name::from_labels(name_parts)
            .map_err(|e| LookupError::ResolveError(ResolveError::from(e)))?;

        // base needs to be computer.name, if the request was _did.alice.computer.name
        if base != self.origin().clone().into() {
            return Ok(AuthLookup::Empty);
        }

        let username = String::from_utf8(user_bytes.to_vec()).map_err(|e| {
            LookupError::ResolveError(
                format!("Failed decoding non-utf8 subdomain segment: {e}").into(),
            )
        })?;

        match first {
            // Serve requests for e.g. _did.alice.computer.name
            Some(b"_did") => {
                tracing::info!(%name, %username, "Looking up DID record");

                let account_did = match self.db_lookup_user_did(username).await {
                    Ok(account_did) => account_did,
                    Err(err) => {
                        tracing::debug!(?err, "Account lookup failed during _did DNS entry lookup");
                        return Ok(AuthLookup::Empty);
                    }
                };

                Ok(AuthLookup::answers(
                    LookupRecords::new(
                        lookup_options,
                        Arc::new(did_record_set(
                            name,
                            account_did,
                            self.default_ttl,
                            self.default_soa.serial(),
                        )),
                    ),
                    None,
                ))
            }
            // Serve requests for volumes e.g. _dnslink.alice.computer.name
            Some(b"_dnslink") => {
                let account_dnslink = match self.db_lookup_user_dnslink(username).await {
                    Ok(Some(account_dnslink)) => account_dnslink,
                    Ok(None) => {
                        // This is perfectly normal. The user just doesn't have an associated volume.
                        return Ok(AuthLookup::Empty);
                    }
                    Err(err) => {
                        tracing::debug!(
                            ?err,
                            "Account lookup failed during _dnslink DNS entry lookup"
                        );
                        return Ok(AuthLookup::Empty);
                    }
                };

                Ok(AuthLookup::answers(
                    LookupRecords::new(
                        lookup_options,
                        Arc::new(did_record_set(
                            name,
                            account_dnslink,
                            self.dnslink_ttl,
                            self.default_soa.serial(),
                        )),
                    ),
                    None,
                ))
            }
            _ => Ok(AuthLookup::Empty),
        }
    }

    async fn search(
        &self,
        request_info: RequestInfo<'_>,
        lookup_options: LookupOptions,
    ) -> Result<Self::Lookup, LookupError> {
        tracing::debug!(query = ?request_info.query, "DNS search matching for user dids.");

        let lookup_name = request_info.query.name();
        let record_type: RecordType = request_info.query.query_type();

        match record_type {
            RecordType::TXT => self.lookup(lookup_name, record_type, lookup_options).await,
            RecordType::SOA => Ok(AuthLookup::answers(
                LookupRecords::new(
                    lookup_options,
                    Arc::new(record_set(
                        &self.origin().into(),
                        record_type,
                        self.default_soa.serial(),
                        Record::from_rdata(
                            self.origin().into(),
                            self.default_ttl,
                            RData::SOA(self.default_soa.clone()),
                        ),
                    )),
                ),
                None,
            )),
            _ => {
                tracing::debug!(
                    %record_type,
                    "Aborting query: only TXT (and SOA) record type(s) supported."
                );
                Ok(AuthLookup::Empty)
            }
        }
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
pub(crate) fn did_record_set(name: &Name, did: String, ttl: u32, serial: u32) -> RecordSet {
    let record = Record::from_rdata(name.clone(), ttl, RData::TXT(TXT::new(vec![did])));
    record_set(name, RecordType::TXT, serial, record)
}

/// Create a record set with a single record inside
pub(crate) fn record_set(
    name: &Name,
    record_type: RecordType,
    serial: u32,
    record: Record,
) -> RecordSet {
    let mut record_set = RecordSet::new(name, record_type, serial);
    record_set.insert(record, serial);
    record_set
}
