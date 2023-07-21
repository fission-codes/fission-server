//! DNS over HTTPS

use std::io;

use anyhow::{bail, ensure, Result};
use axum::{
    async_trait,
    extract::State,
    response::{IntoResponse, Response},
    Json,
};
use bytes::Bytes;
use http::{header::CONTENT_TYPE, StatusCode};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use trust_dns_server::{
    authority::MessageResponse,
    proto::{
        self,
        serialize::binary::{BinDecodable, BinEncoder},
    },
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
};

use crate::{
    db::Pool,
    dns::handler::Handler,
    extract::doh::{DNSMimeType, DNSRequestBody, DNSRequestQuery},
    router::AppState,
};

/// GET handler for resolving DoH queries
pub async fn get(
    State(state): State<AppState>,
    DNSRequestQuery(request, accept_type): DNSRequestQuery,
) -> Response {
    let response = match handle_request(request, state.db_pool).await {
        Ok(response) => response,
        Err(err) => return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    };

    match accept_type {
        DNSMimeType::Message => (
            StatusCode::OK,
            [(CONTENT_TYPE, accept_type.to_string())],
            response,
        )
            .into_response(),
        DNSMimeType::Json => {
            let message = proto::op::Message::from_bytes(&response).unwrap();
            let response = DohResponseJson::from_message(message).unwrap();

            (
                StatusCode::OK,
                [(CONTENT_TYPE, accept_type.to_string())],
                Json(response),
            )
                .into_response()
        }
    }
}

/// POST handler for resolvng DoH queries
pub async fn post(
    State(state): State<AppState>,
    DNSRequestBody(request): DNSRequestBody,
) -> Response {
    let response = match handle_request(request, state.db_pool).await {
        Ok(response) => response,
        Err(err) => return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    };

    (
        StatusCode::OK,
        [(CONTENT_TYPE, DNSMimeType::Message.to_string())],
        response,
    )
        .into_response()
}

async fn handle_request(request: Request, db_pool: Pool) -> Result<Bytes> {
    let (tx, mut rx) = broadcast::channel(1);
    let response_handle = DohResponseHandle(tx);

    Handler::new(db_pool)
        .handle_request(&request, response_handle)
        .await;

    rx.recv().await.map_err(|err| err.into())
}

#[derive(Clone)]
struct DohResponseHandle(broadcast::Sender<Bytes>);

#[async_trait]
impl ResponseHandler for DohResponseHandle {
    async fn send_response<'a>(
        &mut self,
        response: MessageResponse<
            '_,
            'a,
            impl Iterator<Item = &'a proto::rr::Record> + Send + 'a,
            impl Iterator<Item = &'a proto::rr::Record> + Send + 'a,
            impl Iterator<Item = &'a proto::rr::Record> + Send + 'a,
            impl Iterator<Item = &'a proto::rr::Record> + Send + 'a,
        >,
    ) -> io::Result<ResponseInfo> {
        let mut bytes = Vec::with_capacity(512);
        let info = {
            let mut encoder = BinEncoder::new(&mut bytes);
            response.destructive_emit(&mut encoder)?
        };

        let bytes = Bytes::from(bytes);
        self.0.send(bytes).unwrap();

        Ok(info)
    }
}

#[derive(Debug, Serialize, Deserialize)]
/// JSON representation of a DNS response
/// See: https://developers.google.com/speed/public-dns/docs/doh/json
pub struct DohResponseJson {
    /// Standard DNS response code
    #[serde(rename = "Status")]
    status: u32,
    /// Whether the response was truncated
    #[serde(rename = "TC")]
    tc: bool,
    /// Whether recursion was desired
    #[serde(rename = "RD")]
    rd: bool,
    /// Whether recursion was available
    #[serde(rename = "RA")]
    ra: bool,
    /// Whether the response was validated with DNSSEC
    #[serde(rename = "AD")]
    ad: bool,
    /// Whether the client asked to disable DNSSEC validation
    #[serde(rename = "CD")]
    cd: bool,
    #[serde(rename = "Question")]
    question: Vec<DohQuestionJson>,
    #[serde(rename = "Answer")]
    #[serde(default)]
    answer: Vec<DohRecordJson>,
    #[serde(rename = "Comment")]
    comment: Option<String>,
    /// IP Address / scope prefix-length of the client
    /// See: https://tools.ietf.org/html/rfc7871
    edns_client_subnet: Option<String>,
}

impl DohResponseJson {
    /// Create a new JSON response from a DNS message
    pub fn from_message(message: proto::op::Message) -> Result<Self> {
        ensure!(
            message.message_type() == proto::op::MessageType::Response,
            "Expected message type to be response"
        );

        ensure!(
            message.query_count() == message.queries().len() as u16,
            "Query count mismatch"
        );

        ensure!(
            message.answer_count() == message.answers().len() as u16,
            "Answer count mismatch"
        );

        let status: u32 =
            <u16 as From<proto::op::ResponseCode>>::from(message.response_code()) as u32;

        let question: Vec<_> = message
            .queries()
            .iter()
            .map(DohQuestionJson::from_query)
            .collect();

        let answer: Vec<_> = message
            .answers()
            .iter()
            .map(DohRecordJson::from_record)
            .collect::<Result<_>>()?;

        Ok(DohResponseJson {
            status,
            tc: message.truncated(),
            rd: message.recursion_desired(),
            ra: message.recursion_available(),
            ad: message.authentic_data(),
            cd: message.checking_disabled(),
            question,
            answer,
            comment: None,
            edns_client_subnet: None,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
/// JSON representation of a DNS question
pub struct DohQuestionJson {
    /// FQDN with trailing dot
    name: String,
    /// Standard DNS RR type
    #[serde(rename = "type")]
    question_type: u16,
}

impl DohQuestionJson {
    /// Create a new JSON question from a DNS query
    pub fn from_query(query: &proto::op::Query) -> Self {
        Self {
            name: query.name().to_string(),
            question_type: query.query_type().into(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
/// JSON representation of a DNS record
pub struct DohRecordJson {
    /// FQDN with trailing dot
    name: String,
    /// Standard DNS RR type
    #[serde(rename = "type")]
    record_type: u16,
    /// Time-to-live, in seconds
    #[serde(rename = "TTL")]
    ttl: u32,
    /// Record data
    data: String,
}

impl DohRecordJson {
    /// Create a new JSON record from a DNS record
    pub fn from_record(record: &proto::rr::Record) -> Result<Self> {
        let Some(data) = record.data() else {
            bail!("Missing record data");
        };

        Ok(Self {
            name: record.name().to_string(),
            record_type: record.rr_type().into(),
            ttl: record.ttl(),
            data: data.to_string(),
        })
    }
}
