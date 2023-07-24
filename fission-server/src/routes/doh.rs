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

#[cfg(test)]
mod tests {
    use axum::{body::Body, extract::connect_info::MockConnectInfo, http::Request};
    use axum_server::service::SendService;
    use http::StatusCode;
    use serde_json::{json, Value};
    use std::net::SocketAddr;
    use tower::ServiceExt;

    use crate::{
        router::{setup_app_router, AppState},
        test_utils::test_context::TestContext,
    };

    use pretty_assertions::assert_eq;

    #[tokio::test]
    async fn test_dns_json() {
        assert_dns_json(
            "fission.app",
            "soa",
            json!(
                {
                  "Status": 0,
                  "TC": false,
                  "RD": false,
                  "RA": false,
                  "AD": false,
                  "CD": false,
                  "Question": [
                    {
                      "name": "fission.app.",
                      "type": 6
                    }
                  ],
                  "Answer": [
                    {
                      "name": "fission.app.",
                      "type": 6,
                      "TTL": 3600,
                      "data": "dns1.fission.app. hostmaster.fission.codes. 2023000701 7200 3600 1209600 3600"
                    }
                  ],
                  "Comment": null,
                  "edns_client_subnet": null
                }
            ),
        ).await;

        assert_dns_json(
            "gateway.fission.app",
            "any",
            json!(
                {
                  "Status": 0,
                  "TC": false,
                  "RD": false,
                  "RA": false,
                  "AD": false,
                  "CD": false,
                  "Question": [
                    {
                      "name": "gateway.fission.app.",
                      "type": 255
                    }
                  ],
                  "Answer": [
                    {
                      "name": "gateway.fission.app.",
                      "type": 5,
                      "TTL": 3600,
                      "data": "prod-ipfs-gateway-1937066547.us-east-1.elb.amazonaws.com."
                    }
                  ],
                  "Comment": null,
                  "edns_client_subnet": null
                }
            ),
        )
        .await;
    }

    async fn assert_dns_json(name: &str, typ: &str, expected: Value) {
        let ctx = TestContext::new();
        let app_state = AppState {
            db_pool: ctx.pool().await,
        };

        let app = setup_app_router(app_state)
            .layer(MockConnectInfo(SocketAddr::from(([0, 0, 0, 0], 3000))))
            .into_service();

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/dns-query?name={}&type={}", name, typ))
                    .header("Accept", "application/dns-json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(body, expected);
    }
}
