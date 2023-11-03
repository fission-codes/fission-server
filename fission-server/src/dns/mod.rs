//! DNS

use self::response_handler::Handle;
use crate::{
    db::Pool,
    dns::authority::{did_record_set, record_set, DBBackedAuthority, SERIAL},
};
use anyhow::{anyhow, Result};
use bytes::Bytes;
use std::{collections::BTreeMap, sync::Arc};
use tokio::sync::broadcast;
use trust_dns_server::{
    authority::{Authority, Catalog, ZoneType},
    client::{rr::RrKey, serialize::txt::RDataParser},
    proto::rr::{RData, Record, RecordType},
    resolver::{config::NameServerConfigGroup, Name},
    server::{Request, RequestHandler},
    store::{
        forwarder::{ForwardAuthority, ForwardConfig},
        in_memory::InMemoryAuthority,
    },
};

pub mod authority;
pub mod response;
pub mod response_handler;

/// Handle a DNS request
pub async fn handle_request(request: Request, db_pool: Pool, did: String) -> Result<Bytes> {
    let (tx, mut rx) = broadcast::channel(1);
    let response_handle = Handle(tx);

    let catalog = setup_catalog(db_pool, did)?;

    catalog.handle_request(&request, response_handle).await;

    tracing::info!("Fulfilled DNS request");

    Ok(rx.recv().await?)
}

/// Setup the main DNS catalog, which can function as a RequestHandler for DNS requests.
///
/// This sets up three DNS resolving things:
/// - Something that resolves `TXT _did.<thisserver.com>` to return the server's DID
/// - Something that resolves `TXT _did.<username>.<thisserver.com>` to return user DIDs
/// - Something that forwards any DNS requests to cloudflare via DNS-over-TLS.
pub fn setup_catalog(db_pool: Pool, server_did: String) -> Result<Catalog> {
    let fission_soa = RData::parse(
        RecordType::SOA,
        [
            "dns1.fission.systems",
            "hostmaster.fission.codes",
            "2023000701",
            "10800",
            "3600",
            "604800",
            "3600",
        ]
        .into_iter(),
        None,
    )
    .map_err(|e| anyhow!(e))?;

    let origin_name = Name::from_ascii("localhost.").expect("Invalid hardcoded domain name.");
    let server_did_name =
        Name::from_ascii("_did.localhost.").expect("Invalid hardcoded domain name.");
    let did_rset = did_record_set(&server_did_name, server_did);
    let server_did_authority = InMemoryAuthority::new(
        server_did_name.clone(),
        BTreeMap::from([
            (
                RrKey::new(server_did_name.clone().into(), RecordType::TXT),
                did_rset,
            ),
            (
                RrKey::new(server_did_name.clone().into(), RecordType::SOA),
                record_set(
                    &server_did_name,
                    RecordType::SOA,
                    SERIAL,
                    Record::from_rdata(server_did_name.clone(), 1209600, fission_soa),
                ),
            ),
        ]),
        ZoneType::Primary,
        false,
    )
    .map_err(|e| anyhow!(e))?;

    let db_authority = DBBackedAuthority::new(db_pool, origin_name.into());

    let config = ForwardConfig {
        name_servers: NameServerConfigGroup::cloudflare_tls(),
        options: None,
    };

    let forwarder = ForwardAuthority::try_from_config(Name::root(), ZoneType::Forward, &config)
        .map_err(|e| anyhow!(e))?;

    let mut catalog = Catalog::new();
    catalog.upsert(
        db_authority.origin().clone(),
        Box::new(Arc::new(db_authority)),
    );
    catalog.upsert(
        server_did_authority.origin().clone(),
        Box::new(Arc::new(server_did_authority)),
    );
    catalog.upsert(Name::root().into(), Box::new(Arc::new(forwarder)));

    Ok(catalog)
}
