//! Extractors for DNS-over-HTTPS requests
use std::{
    fmt::{self, Display, Formatter},
    net::SocketAddr,
    str::FromStr,
};

use async_trait::async_trait;
use axum::{
    extract::{ConnectInfo, FromRequest, FromRequestParts, Query},
    http::Request,
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use http::{header, request::Parts, StatusCode};
use serde::Deserialize;
use trust_dns_server::{
    authority::MessageRequest,
    proto::{
        self,
        serialize::binary::{BinDecodable, BinDecoder, BinEncodable, BinEncoder},
    },
    server::{Protocol, Request as DNSRequest},
};

/// A DNS packet encoding type
#[derive(Debug)]
pub enum DNSMimeType {
    /// application/dns-message
    Message,
    /// application/dns-json
    Json,
}

impl Display for DNSMimeType {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            DNSMimeType::Message => write!(f, "application/dns-message"),
            DNSMimeType::Json => write!(f, "application/dns-json"),
        }
    }
}

#[derive(Debug, Deserialize)]
struct DNSMessageQuery {
    dns: String,
}

/// See: https://developers.google.com/speed/public-dns/docs/doh/json#supported_parameters
#[derive(Debug, Deserialize)]
struct DNSJsonQuery {
    name: String,
    #[serde(rename = "type")]
    record_type: Option<String>,
    cd: Option<bool>,
    #[allow(dead_code)]
    ct: Option<String>,
    #[serde(rename = "do")]
    dnssec_ok: Option<bool>,
    #[allow(dead_code)]
    edns_client_subnet: Option<String>,
    #[allow(dead_code)]
    random_padding: Option<String>,
    #[serde(rename = "rd")]
    recursion_desired: Option<bool>,
}

/// A DNS request encoded in the query string
#[derive(Debug)]
pub struct DNSRequestQuery(pub(crate) DNSRequest, pub(crate) DNSMimeType);

/// A DNS request encoded in the body
#[derive(Debug)]
pub struct DNSRequestBody(pub(crate) DNSRequest);

#[async_trait]
impl<S> FromRequestParts<S> for DNSRequestQuery
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let ConnectInfo(src_addr) = ConnectInfo::from_request_parts(parts, state)
            .await
            .map_err(|err| err.into_response())?;

        match parts.headers.get(header::ACCEPT) {
            Some(content_type) if content_type == "application/dns-message" => {
                handle_dns_message_query(parts, state, src_addr).await
            }
            Some(content_type) if content_type == "application/dns-json" => {
                handle_dns_json_query(parts, state, src_addr).await
            }
            Some(content_type) if content_type == "application/x-javascript" => {
                handle_dns_json_query(parts, state, src_addr).await
            }
            None => handle_dns_message_query(parts, state, src_addr).await,
            _ => Err(StatusCode::NOT_ACCEPTABLE.into_response()),
        }
    }
}

#[async_trait]
impl<S, B> FromRequest<S, B> for DNSRequestBody
where
    Bytes: FromRequest<S, B>,
    S: Send + Sync,
    B: Send + 'static,
{
    type Rejection = Response;

    async fn from_request(req: Request<B>, state: &S) -> Result<Self, Self::Rejection> {
        let (mut parts, body) = req.into_parts();

        let ConnectInfo(src_addr) = ConnectInfo::from_request_parts(&mut parts, state)
            .await
            .map_err(|err| err.into_response())?;

        let req = Request::from_parts(parts, body);

        let body = Bytes::from_request(req, state)
            .await
            .map_err(IntoResponse::into_response)?;

        let request = decode_request(&body, src_addr)?;

        Ok(DNSRequestBody(request))
    }
}

async fn handle_dns_message_query<S>(
    parts: &mut Parts,
    state: &S,
    src_addr: SocketAddr,
) -> Result<DNSRequestQuery, Response>
where
    S: Send + Sync,
{
    let Query(params) = Query::<DNSMessageQuery>::from_request_parts(parts, state)
        .await
        .map_err(|err| err.into_response())?;

    let buf = base64_url::decode(params.dns.as_bytes())
        .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()).into_response())?;

    let request = decode_request(&buf, src_addr)?;

    Ok(DNSRequestQuery(request, DNSMimeType::Message))
}

async fn handle_dns_json_query<S>(
    parts: &mut Parts,
    state: &S,
    src_addr: SocketAddr,
) -> Result<DNSRequestQuery, Response>
where
    S: Send + Sync,
{
    let Query(params) = Query::<DNSJsonQuery>::from_request_parts(parts, state)
        .await
        .map_err(|err| err.into_response())?;

    let query_type = if let Some(record_type) = params.record_type {
        record_type
            .parse::<u16>()
            .map(proto::rr::RecordType::from)
            .or_else(|_| FromStr::from_str(&record_type.to_uppercase()))
            .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()).into_response())?
    } else {
        proto::rr::RecordType::A
    };

    let name = proto::rr::Name::from_utf8(params.name)
        .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()).into_response())?;

    let query = proto::op::Query::query(name, query_type);

    let mut message = proto::op::Message::new();

    message
        .add_query(query)
        .set_message_type(proto::op::MessageType::Query)
        .set_op_code(proto::op::OpCode::Query)
        .set_checking_disabled(params.cd.unwrap_or(false))
        .set_recursion_desired(params.recursion_desired.unwrap_or(true))
        .set_recursion_available(true)
        .set_authentic_data(params.dnssec_ok.unwrap_or(false));

    // This is kind of a hack, but the only way I can find to
    // create a MessageRequest is by decoding a buffer of bytes,
    // so we encode the message into a buffer and then decode it
    let mut buf = Vec::with_capacity(4096);
    let mut encoder = BinEncoder::new(&mut buf);

    message
        .emit(&mut encoder)
        .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()).into_response())?;

    let request = decode_request(&buf, src_addr)?;

    Ok(DNSRequestQuery(request, DNSMimeType::Json))
}

fn decode_request(bytes: &[u8], src_addr: SocketAddr) -> Result<DNSRequest, Response> {
    let mut decoder = BinDecoder::new(bytes);

    match MessageRequest::read(&mut decoder) {
        Ok(message) => {
            if message.message_type() != proto::op::MessageType::Query {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "Invalid message type: expected query",
                )
                    .into_response());
            }

            let request = DNSRequest::new(message, src_addr, Protocol::Https);

            Ok(request)
        }
        Err(err) => Err((
            StatusCode::BAD_REQUEST,
            format!("Invalid DNS message: {}", err),
        )
            .into_response()),
    }
}
