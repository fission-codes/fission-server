//! DNS over HTTPS

use crate::{
    app_state::AppState,
    extract::doh::{DNSMimeType, DNSRequestBody, DNSRequestQuery},
    setups::ServerSetup,
};
use axum::{
    extract::State,
    response::{IntoResponse, Response},
    Json,
};
use fission_core::dns;
use hickory_server::proto::{self, serialize::binary::BinDecodable};
use http::{header::CONTENT_TYPE, StatusCode};

/// GET handler for resolving DoH queries
pub async fn get<S: ServerSetup>(
    State(state): State<AppState<S>>,
    DNSRequestQuery(request, accept_type): DNSRequestQuery,
) -> Response {
    let response = match state.dns_server.answer_request(request).await {
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
pub async fn post<S: ServerSetup>(
    State(state): State<AppState<S>>,
    DNSRequestBody(request): DNSRequestBody,
) -> Response {
    let response = match state.dns_server.answer_request(request).await {
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
    use crate::{
        db::schema::accounts,
        test_utils::{route_builder::RouteBuilder, test_context::TestContext},
    };
    use diesel::ExpressionMethods;
    use diesel_async::RunQueryDsl;
    use http::{Method, StatusCode};
    use mime::Mime;
    use pretty_assertions::assert_eq;
    use rs_ucan::DefaultFact;
    use serde_json::json;
    use std::str::FromStr;
    use testresult::TestResult;

    #[test_log::test(tokio::test)]
    async fn test_dns_json_soa() -> TestResult {
        let ctx = TestContext::new().await;

        let (status, body) = RouteBuilder::<DefaultFact>::new(
            ctx.app(),
            Method::GET,
            format!("/dns-query?name={}&type={}", "localhost", "soa"),
        )
        .with_accept_mime(Mime::from_str("application/dns-json")?)
        .into_json_response::<serde_json::Value>()
        .await?;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body,
            json!(
                {
                  "Status": 0,
                  "TC": false,
                  "RD": true,
                  "RA": false,
                  "AD": false,
                  "CD": false,
                  "Question": [
                    {
                      "name": "localhost.",
                      "type": 6
                    }
                  ],
                  "Answer": [
                    {
                      "name": "localhost.",
                      "type": 6,
                      "TTL": 1800,
                      "data": "dns1.fission.systems. hostmaster.fission.codes. 0 10800 3600 604800 3600"
                    }
                  ],
                  "Comment": null,
                  "edns_client_subnet": null
                }
            ),
        );

        Ok(())
    }

    #[test_log::test(tokio::test)]
    async fn test_dns_json_did_username_ok() -> TestResult {
        let ctx = TestContext::new().await;
        let mut conn = ctx.get_db_conn().await;

        let username = "donnie";
        let email = "donnie@example.com";
        let did = "did:28:06:42:12";

        diesel::insert_into(accounts::table)
            .values((
                accounts::username.eq(username),
                accounts::email.eq(email),
                accounts::did.eq(did),
            ))
            .execute(&mut conn)
            .await?;

        let (status, body) = RouteBuilder::<DefaultFact>::new(
            ctx.app(),
            Method::GET,
            format!(
                "/dns-query?name={}&type={}",
                format_args!("_did.{}.localhost", username),
                "txt"
            ),
        )
        .with_accept_mime(Mime::from_str("application/dns-json")?)
        .into_json_response::<serde_json::Value>()
        .await?;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body,
            json!(
                {
                  "Status": 0,
                  "TC": false,
                  "RD": true,
                  "RA": false,
                  "AD": false,
                  "CD": false,
                  "Question": [
                    {
                      "name": "_did.donnie.localhost.",
                      "type": 16
                    }
                  ],
                  "Answer": [
                    {
                      "name": "_did.donnie.localhost.",
                      "type": 16,
                      "TTL": 1800,
                      "data": "did:28:06:42:12"
                    }
                  ],
                  "Comment": null,
                  "edns_client_subnet": null
                }
            ),
        );

        Ok(())
    }

    #[test_log::test(tokio::test)]
    async fn test_dns_json_did_username_err_not_found() -> TestResult {
        let ctx = TestContext::new().await;
        let username = "donnie";

        let (status, body) = RouteBuilder::<DefaultFact>::new(
            ctx.app(),
            Method::GET,
            format!(
                "/dns-query?name={}&type={}",
                format_args!("_did.{}.localhost", username),
                "txt"
            ),
        )
        .with_accept_mime(Mime::from_str("application/dns-json")?)
        .into_json_response::<serde_json::Value>()
        .await?;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body,
            json!(
                {
                  "Status": 0,
                  "TC": false,
                  "RD": true,
                  "RA": false,
                  "AD": false,
                  "CD": false,
                  "Question": [
                    {
                      "name": "_did.donnie.localhost.",
                      "type": 16
                    }
                  ],
                  "Comment": null,
                  "edns_client_subnet": null
                }
            ),
        );

        Ok(())
    }
}
