//! DNS Request Handler

use async_trait::async_trait;
use core::fmt;
use futures::Future;
use std::{borrow::Borrow, str::FromStr};
use tracing::error;
use trust_dns_server::{
    authority::{
        AuthLookup, Authority, LookupError, LookupOptions, LookupRecords, MessageResponseBuilder,
        ZoneType,
    },
    client::op::LowerQuery,
    proto::{
        op::{Edns, Header, ResponseCode},
        rr::{
            rdata::{SOA, TXT},
            RData, Record,
        },
    },
    resolver::Name,
    server::{Request, RequestHandler, RequestInfo, ResponseHandler, ResponseInfo},
    store::in_memory::InMemoryAuthority,
};

use crate::{
    db::{self, Pool},
    models::account::Account,
};

/// DNS Request Handler

pub struct DBBackedAuthority {
    #[allow(dead_code)]
    db_pool: Pool,
}

impl fmt::Debug for DBBackedAuthority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Handler").finish()
    }
}

impl DBBackedAuthority {
    /// Create a new database backed authority
    pub fn new(db_pool: Pool) -> Self {
        DBBackedAuthority { db_pool }
    }
}

/// Handle a DNS request for the Fission Server
impl DBBackedAuthority {
    async fn do_handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        let mut authority = InMemoryAuthority::empty(
            Name::from_str("fission.app.").expect("invalid zone name"),
            ZoneType::Primary,
            false,
        );

        authority.upsert_mut(
            Record::from_rdata(
                Name::from_str("fission.app.").expect("invalid record name"),
                3600,
                RData::SOA(SOA::new(
                    Name::from_str("dns1.fission.app.").expect("invalid mname"),
                    Name::from_str("hostmaster.fission.codes.").expect("invalid rname"),
                    2023000701,
                    7200,
                    3600,
                    1209600,
                    3600,
                )),
            ),
            0,
        );

        authority.upsert_mut(
            Record::from_rdata(
                Name::from_ascii("gateway.fission.app").expect("invalid record name"),
                3600,
                RData::CNAME(
                    Name::from_ascii("prod-ipfs-gateway-1937066547.us-east-1.elb.amazonaws.com.")
                        .expect("invalid record name"),
                ),
            ),
            0,
        );

        let request_info = request.request_info();
        let query = request_info.query;

        let (prefix, base) = {
            let name: &Name = query.name().borrow();
            let mut iter = name.iter();

            (iter.next(), name.base_name())
        };

        if let Some(prefix) = prefix {
            match prefix {
                b"_dnslink" => self.insert_dnslink_records(&mut authority, base).await,
                b"_atproto" => self.insert_atproto_records(&mut authority, base).await,
                _ => (),
            }
        }

        let (response_header, sections) = build_response(
            &authority,
            request_info,
            request.id(),
            request.header(),
            query,
            request.edns(),
        )
        .await;

        let response = MessageResponseBuilder::from_message_request(request).build(
            response_header,
            sections.answers.iter(),
            sections.ns.iter(),
            sections.soa.iter(),
            sections.additionals.iter(),
        );

        let result = response_handle.send_response(response).await;

        match result {
            Ok(i) => i,
            Err(e) => {
                error!("Error sending response: {}", e);

                let mut header = Header::new();
                header.set_response_code(ResponseCode::ServFail);
                header.into()
            }
        }
    }

    async fn insert_dnslink_records(&self, authority: &mut InMemoryAuthority, base: Name) {
        let mut conn = db::connect(&self.db_pool).await.unwrap();

        let Some(Ok(username)) = ({
            let mut iter = base.iter();

            iter.next().map(std::str::from_utf8)
        }) else {
            return;
        };

        let Ok(account) = Account::find_by_username(&mut conn, username).await else {
            return;
        };

        let name = Name::from_ascii("_dnslink")
            .expect("invalid record name")
            .append_domain(&base)
            .expect("invalid record name");

        authority.upsert_mut(
            Record::from_rdata(name, 60, RData::TXT(TXT::new(vec![account.did]))),
            0,
        );
    }

    async fn insert_atproto_records(&self, _authority: &mut InMemoryAuthority, _base: Name) {
        todo!();
    }
}

#[async_trait]
impl RequestHandler for DBBackedAuthority {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        responder: R,
    ) -> ResponseInfo {
        self.do_handle_request(request, responder).await
    }
}

async fn build_response(
    authority: &InMemoryAuthority,
    request_info: RequestInfo<'_>,
    request_id: u16,
    request_header: &Header,
    query: &LowerQuery,
    _edns: Option<&Edns>,
) -> (Header, LookupSections) {
    let lookup_options = LookupOptions::default();

    let mut response_header = Header::response_from_request(request_header);
    response_header.set_authoritative(authority.zone_type().is_authoritative());

    let future = authority.search(request_info, lookup_options);

    #[allow(deprecated)]
    let sections = match authority.zone_type() {
        ZoneType::Primary | ZoneType::Secondary | ZoneType::Master | ZoneType::Slave => {
            send_authoritative_response(
                future,
                authority,
                &mut response_header,
                lookup_options,
                request_id,
                query,
            )
            .await
        }
        ZoneType::Forward | ZoneType::Hint => {
            send_forwarded_response(future, request_header, &mut response_header).await
        }
    };

    (response_header, sections)
}

async fn send_authoritative_response(
    future: impl Future<Output = Result<AuthLookup, LookupError>>,
    authority: &InMemoryAuthority,
    response_header: &mut Header,
    lookup_options: LookupOptions,
    _request_id: u16,
    query: &LowerQuery,
) -> LookupSections {
    let answers = match future.await {
        Ok(records) => {
            response_header.set_response_code(ResponseCode::NoError);
            response_header.set_authoritative(true);

            Some(records)
        }
        Err(LookupError::ResponseCode(ResponseCode::Refused)) => {
            response_header.set_response_code(ResponseCode::Refused);

            return LookupSections {
                answers: AuthLookup::default(),
                ns: AuthLookup::default(),
                soa: AuthLookup::default(),
                additionals: LookupRecords::default(),
            };
        }
        Err(e) => {
            if e.is_nx_domain() {
                response_header.set_response_code(ResponseCode::NXDomain);
            } else if e.is_name_exists() {
                response_header.set_response_code(ResponseCode::NoError);
            }

            None
        }
    };

    let (ns, soa) = if answers.is_some() {
        if query.query_type().is_soa() {
            match authority.ns(lookup_options).await {
                Ok(ns) => (Some(ns), None),
                Err(_) => (None, None),
            }
        } else {
            (None, None)
        }
    } else {
        (None, None)
    };

    let (answers, additionals) = match answers {
        Some(mut answers) => match answers.take_additionals() {
            Some(additionals) => (answers, additionals),
            None => (answers, LookupRecords::default()),
        },
        None => (AuthLookup::default(), LookupRecords::default()),
    };

    LookupSections {
        answers,
        ns: ns.unwrap_or_default(),
        soa: soa.unwrap_or_default(),
        additionals,
    }
}

async fn send_forwarded_response(
    _future: impl Future<Output = Result<AuthLookup, LookupError>>,
    _request_header: &Header,
    _response_header: &mut Header,
) -> LookupSections {
    todo!();
}

struct LookupSections {
    answers: AuthLookup,
    ns: AuthLookup,
    soa: AuthLookup,
    additionals: LookupRecords,
}
