//! DNS Request Handler

use std::{
    borrow::Borrow,
    str,
    str::{FromStr, Utf8Error},
};

use trust_dns_proto::rr::rdata::SOA;
use trust_dns_server::{
    authority::MessageResponseBuilder,
    client::rr::{LowerName, Name},
    proto::{
        error::ProtoError,
        op::{Header, MessageType, OpCode, ResponseCode},
        rr::{rdata::TXT, RData, Record, RecordType},
    },
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
};

use tracing::error;

use crate::{
    db::{self, Pool},
    models::account::Account,
};

/// Error type for DNS handler
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// Invalid Op Code
    #[error("Invalid OpCode {0:}")]
    InvalidOpCode(OpCode),
    /// Invalid Message Type
    #[error("Invalid MessageType {0:}")]
    InvalidMessageType(MessageType),
    /// Invalid Zone
    #[error("Invalid Zone {0:}")]
    InvalidZone(LowerName),
    /// IO Error
    #[error("IO error: {0:}")]
    Io(#[from] std::io::Error),
}

// FIXME this is really not right
impl From<anyhow::Error> for Error {
    fn from(e: anyhow::Error) -> Self {
        Error::Io(std::io::Error::new(std::io::ErrorKind::Other, e))
    }
}

// FIXME this is really not right
impl From<diesel::result::Error> for Error {
    fn from(e: diesel::result::Error) -> Self {
        Error::Io(std::io::Error::new(std::io::ErrorKind::Other, e))
    }
}

impl From<Utf8Error> for Error {
    fn from(e: Utf8Error) -> Self {
        Error::Io(std::io::Error::new(std::io::ErrorKind::Other, e))
    }
}

impl From<ProtoError> for Error {
    fn from(e: ProtoError) -> Self {
        Error::Io(std::io::Error::new(std::io::ErrorKind::Other, e))
    }
}

/// DNS Request Handler
#[derive(Clone, Debug)]
pub struct Handler {
    db_pool: Pool,
    fission_zone: LowerName,
}

impl Handler {
    /// Create new handler from command-line options.
    pub fn new(db_pool: Pool) -> Self {
        Handler {
            db_pool,
            fission_zone: LowerName::from(Name::from_str("fission.app").unwrap()),
        }
    }
}

/// Handle a DNS request for the Fission Server
impl Handler {
    async fn do_handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        responder: R,
    ) -> Result<ResponseInfo, Error> {
        // make sure the request is a query
        if request.op_code() != OpCode::Query {
            return Err(Error::InvalidOpCode(request.op_code()));
        }

        // make sure the message type is a query
        if request.message_type() != MessageType::Query {
            return Err(Error::InvalidMessageType(request.message_type()));
        }

        match request.query().name() {
            name if self.fission_zone.zone_of(name) => {
                self.do_handle_request_fission(request, responder).await
            }
            _ => self.empty_response(request, responder).await,
        }
    }

    fn fission_soa(&self) -> Vec<Record> {
        let domain_name = Name::from_str("fission.app.").unwrap();
        let mname = Name::from_str("dns1.fission.app.").unwrap();
        let rname = Name::from_str("hostmaster.fission.codes.").unwrap();

        let rdata = RData::SOA(SOA::new(
            mname, rname, 2023000701, 7200, 3600, 1209600, 3600,
        ));

        vec![Record::from_rdata(domain_name, 3600, rdata)]
    }

    fn fission_gateway_record(&self) -> Record {
        let rdata = RData::CNAME(
            Name::from_ascii("prod-ipfs-gateway-1937066547.us-east-1.elb.amazonaws.com.").unwrap(),
        );
        Record::from_rdata(Name::from_ascii("gateway.fission.app").unwrap(), 300, rdata)
    }

    async fn empty_response<R: ResponseHandler>(
        &self,
        request: &Request,
        mut responder: R,
    ) -> Result<ResponseInfo, Error> {
        let builder = MessageResponseBuilder::from_message_request(request);
        let mut header = Header::response_from_request(request.header());
        header.set_authoritative(false);

        let soa = self.fission_soa();
        let response = builder.build(header, &[], &[], soa.iter(), &[]);
        Ok(responder.send_response(response).await?)
    }

    async fn do_handle_request_fission<R: ResponseHandler>(
        &self,
        request: &Request,
        responder: R,
    ) -> Result<ResponseInfo, Error> {
        let name: &Name = request.query().name().borrow();
        let mut name_iter = name.iter();

        let hostname = name_iter.next();
        if hostname.is_none() {
            return self.empty_response(request, responder).await;
        }

        let Some(hostname) = hostname else {
            return self.empty_response(request, responder).await;
        };

        match str::from_utf8(hostname)? {
            "gateway" => {
                self.do_handle_request_fission_gateway(request, responder)
                    .await
            }
            "_dnslink" => match request.query().query_type() {
                RecordType::TXT => {
                    let Some(host) = name_iter.next() else {
                        return self.empty_response(request, responder).await;
                    };
                    let host = LowerName::from_str(str::from_utf8(host)?)?;
                    self.do_handle_request_dnslink(request, responder, host)
                        .await
                }
                _ => self.empty_response(request, responder).await,
            },
            "_atproto" => match request.query().query_type() {
                RecordType::TXT => self.do_handle_request_atproto(request, responder).await,
                _ => self.empty_response(request, responder).await,
            },
            _ => {
                self.do_handle_request_app_hostname(
                    request,
                    responder,
                    LowerName::from_str(str::from_utf8(hostname)?)?,
                )
                .await
            }
        }
    }

    async fn do_handle_request_app_hostname<R: ResponseHandler>(
        &self,
        request: &Request,
        mut responder: R,
        _hostname: LowerName,
    ) -> Result<ResponseInfo, Error> {
        let builder = MessageResponseBuilder::from_message_request(request);
        let mut header = Header::response_from_request(request.header());
        header.set_authoritative(true);

        let records = vec![
            self.fission_gateway_cname(request.query().name().into()),
            self.fission_gateway_record(),
        ];
        let soa = self.fission_soa();
        let response = builder.build(header, records.iter(), &[], soa.iter(), &[]);

        Ok(responder.send_response(response).await?)
    }

    fn fission_gateway_cname(&self, host: Name) -> Record {
        let rdata = RData::CNAME(Name::from_ascii("gateway.fission.app").unwrap());
        Record::from_rdata(host, 300, rdata)
    }

    async fn do_handle_request_fission_gateway<R: ResponseHandler>(
        &self,
        request: &Request,
        mut responder: R,
    ) -> Result<ResponseInfo, Error> {
        let builder = MessageResponseBuilder::from_message_request(request);
        let mut header = Header::response_from_request(request.header());
        header.set_authoritative(true);

        let records = vec![self.fission_gateway_record()];
        let response = builder.build(header, records.iter(), &[], &[], &[]);

        Ok(responder.send_response(response).await?)
    }

    async fn do_handle_request_dnslink<R: ResponseHandler>(
        &self,
        request: &Request,
        mut responder: R,
        hostname: LowerName,
    ) -> Result<ResponseInfo, Error> {
        let builder = MessageResponseBuilder::from_message_request(request);
        let mut header = Header::response_from_request(request.header());
        header.set_authoritative(true);

        let mut conn = db::connect(&self.db_pool).await?;

        // FIXME this needs to fetch from apps, not users.
        let account = Account::find_by_username(&mut conn, hostname.to_string()).await?;
        let did = account.did;

        let rdata = RData::TXT(TXT::new(vec![did]));
        let records = vec![Record::from_rdata(request.query().name().into(), 60, rdata)];
        let response = builder.build(header, records.iter(), &[], &[], &[]);

        Ok(responder.send_response(response).await?)
    }

    async fn do_handle_request_atproto<R: ResponseHandler>(
        &self,
        _request: &Request,
        mut _responder: R,
    ) -> Result<ResponseInfo, Error> {
        todo!()
    }
}

#[async_trait::async_trait]
impl RequestHandler for Handler {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        responder: R,
    ) -> ResponseInfo {
        // try to handle request
        match self.do_handle_request(request, responder).await {
            Ok(info) => info,
            Err(error) => {
                error!("Error in RequestHandler: {error}");
                let mut header = Header::new();
                header.set_response_code(ResponseCode::ServFail);
                header.into()
            }
        }
    }
}
