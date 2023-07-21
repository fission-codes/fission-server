//! DNS over HTTPS

use axum::{
    extract::State,
    response::{IntoResponse, Response},
    Json,
};
use http::{header::CONTENT_TYPE, StatusCode};
use trust_dns_server::proto::{self, serialize::binary::BinDecodable};

use crate::{
    dns,
    extract::doh::{DNSMimeType, DNSRequestBody, DNSRequestQuery},
    router::AppState,
};

/// GET handler for resolving DoH queries
pub async fn get(
    State(state): State<AppState>,
    DNSRequestQuery(request, accept_type): DNSRequestQuery,
) -> Response {
    let response = match dns::handle_request(request, state.db_pool).await {
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
            let response = dns::Response::from_message(message).unwrap();

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
    let response = match dns::handle_request(request, state.db_pool).await {
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
