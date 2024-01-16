//! Extractors for DNS-over-HTTPS requests
use crate::error::AppError;
use async_trait::async_trait;
use axum::{
    extract::{ConnectInfo, FromRequest, FromRequestParts, Query},
    http::Request,
};
use bytes::Bytes;
use hickory_server::{
    authority::MessageRequest,
    proto::{
        self,
        rr::RecordType,
        serialize::binary::{BinDecodable, BinDecoder, BinEncodable, BinEncoder},
    },
    server::{Protocol, Request as DNSRequest},
};
use http::{header, request::Parts, HeaderValue, StatusCode};
use serde::Deserialize;
use std::{
    fmt::{self, Display, Formatter},
    net::SocketAddr,
    str::FromStr,
};

/// A DNS packet encoding type
#[derive(Debug)]
pub enum DnsMimeType {
    /// application/dns-message
    Message,
    /// application/dns-json
    Json,
}

impl Display for DnsMimeType {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            DnsMimeType::Message => write!(f, "application/dns-message"),
            DnsMimeType::Json => write!(f, "application/dns-json"),
        }
    }
}

impl DnsMimeType {
    /// Turn this mime type to an `Accept` HTTP header value
    pub fn to_header_value(&self) -> HeaderValue {
        HeaderValue::from_static(match self {
            Self::Message => "application/dns-message",
            Self::Json => "application/dns-json",
        })
    }
}

#[derive(Debug, Deserialize)]
struct DnsMessageQuery {
    dns: String,
}

/// See: https://developers.google.com/speed/public-dns/docs/doh/json#supported_parameters
#[derive(Debug, Deserialize)]
pub struct DnsQuery {
    /// Record name to look up, e.g. example.com
    pub name: String,
    /// Record type, e.g. A/AAAA/TXT, etc.
    #[serde(rename = "type")]
    pub record_type: Option<String>,
    /// Used to disable DNSSEC validation
    pub cd: Option<bool>,
    /// Desired content type. E.g. "application/dns-message" or "application/dns-json"
    #[allow(dead_code)]
    pub ct: Option<String>,
    /// Whether to return DNSSEC entries such as RRSIG, NSEC or NSEC3
    #[serde(rename = "do")]
    pub dnssec_ok: Option<bool>,
    /// Privacy setting for how your IP address is forwarded to authoritative nameservers
    #[allow(dead_code)]
    pub edns_client_subnet: Option<String>,
    /// Some url-safe random characters to pad your messages for privacy (to avoid being fingerprinted by encrytped message length)
    #[allow(dead_code)]
    pub random_padding: Option<String>,
    /// Whether to provide answers for all records up to the root
    #[serde(rename = "rd")]
    pub recursion_desired: Option<bool>,
}

impl DnsQuery {
    /// Construct a new query for a record with a given type
    pub fn new(name: String, record_type: RecordType) -> Self {
        Self {
            name,
            record_type: Some(record_type.to_string()),
            cd: None,
            ct: None,
            dnssec_ok: None,
            edns_client_subnet: None,
            random_padding: None,
            recursion_desired: None,
        }
    }
}

/// A DNS request encoded in the query string
#[derive(Debug)]
pub struct DnsRequestQuery(pub(crate) DNSRequest, pub(crate) DnsMimeType);

/// A DNS request encoded in the body
#[derive(Debug)]
pub struct DnsRequestBody(pub(crate) DNSRequest);

#[async_trait]
impl<S> FromRequestParts<S> for DnsRequestQuery
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let ConnectInfo(src_addr) = ConnectInfo::from_request_parts(parts, state).await?;

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
            _ => Err(AppError::new::<String>(StatusCode::NOT_ACCEPTABLE, None)),
        }
    }
}

#[async_trait]
impl<S, B> FromRequest<S, B> for DnsRequestBody
where
    Bytes: FromRequest<S, B>,
    S: Send + Sync,
    B: Send + 'static,
{
    type Rejection = AppError;

    async fn from_request(req: Request<B>, state: &S) -> Result<Self, Self::Rejection> {
        let (mut parts, body) = req.into_parts();

        let ConnectInfo(src_addr) = ConnectInfo::from_request_parts(&mut parts, state).await?;

        let req = Request::from_parts(parts, body);

        let body = Bytes::from_request(req, state)
            .await
            .map_err(|_| AppError::new::<String>(StatusCode::INTERNAL_SERVER_ERROR, None))?;

        let request = decode_request(&body, src_addr)?;

        Ok(DnsRequestBody(request))
    }
}

async fn handle_dns_message_query<S>(
    parts: &mut Parts,
    state: &S,
    src_addr: SocketAddr,
) -> Result<DnsRequestQuery, AppError>
where
    S: Send + Sync,
{
    let Query(params) = Query::<DnsMessageQuery>::from_request_parts(parts, state).await?;

    let buf = base64_url::decode(params.dns.as_bytes())
        .map_err(|err| AppError::new(StatusCode::BAD_REQUEST, Some(err)))?;

    let request = decode_request(&buf, src_addr)?;

    Ok(DnsRequestQuery(request, DnsMimeType::Message))
}

async fn handle_dns_json_query<S>(
    parts: &mut Parts,
    state: &S,
    src_addr: SocketAddr,
) -> Result<DnsRequestQuery, AppError>
where
    S: Send + Sync,
{
    let Query(dns_query) = Query::<DnsQuery>::from_request_parts(parts, state).await?;

    let request = encode_query_as_request(dns_query, src_addr)?;

    Ok(DnsRequestQuery(request, DnsMimeType::Json))
}

/// Exposed to make it usable internally...
pub(crate) fn encode_query_as_request(
    question: DnsQuery,
    src_addr: SocketAddr,
) -> Result<DNSRequest, AppError> {
    let query_type = if let Some(record_type) = question.record_type {
        record_type
            .parse::<u16>()
            .map(proto::rr::RecordType::from)
            .or_else(|_| FromStr::from_str(&record_type.to_uppercase()))
            .map_err(|err| AppError::new(StatusCode::BAD_REQUEST, Some(err)))?
    } else {
        proto::rr::RecordType::A
    };

    let name = proto::rr::Name::from_utf8(question.name)
        .map_err(|err| AppError::new(StatusCode::BAD_REQUEST, Some(err)))?;

    let query = proto::op::Query::query(name, query_type);

    let mut message = proto::op::Message::new();

    message
        .add_query(query)
        .set_message_type(proto::op::MessageType::Query)
        .set_op_code(proto::op::OpCode::Query)
        .set_checking_disabled(question.cd.unwrap_or(false))
        .set_recursion_desired(question.recursion_desired.unwrap_or(true))
        .set_recursion_available(true)
        .set_authentic_data(question.dnssec_ok.unwrap_or(false));

    // This is kind of a hack, but the only way I can find to
    // create a MessageRequest is by decoding a buffer of bytes,
    // so we encode the message into a buffer and then decode it
    let mut buf = Vec::with_capacity(4096);
    let mut encoder = BinEncoder::new(&mut buf);

    message
        .emit(&mut encoder)
        .map_err(|err| AppError::new(StatusCode::BAD_REQUEST, Some(err)))?;

    let request = decode_request(&buf, src_addr)?;

    Ok(request)
}

fn decode_request(bytes: &[u8], src_addr: SocketAddr) -> Result<DNSRequest, AppError> {
    let mut decoder = BinDecoder::new(bytes);

    match MessageRequest::read(&mut decoder) {
        Ok(message) => {
            if message.message_type() != proto::op::MessageType::Query {
                return Err(AppError::new(
                    StatusCode::BAD_REQUEST,
                    Some("Invalid message type: expected query"),
                ));
            }

            let request = DNSRequest::new(message, src_addr, Protocol::Https);

            Ok(request)
        }
        Err(err) => Err(AppError::new(
            StatusCode::BAD_REQUEST,
            Some(format!("Invalid DNS message: {}", err)),
        )),
    }
}
