//! DNS over HTTPS

use axum::{
    extract::State,
    response::{IntoResponse, Response},
    Json,
};
use http::{header::CONTENT_TYPE, StatusCode};
use trust_dns_server::proto::{self, serialize::binary::BinDecodable};

use crate::{
    app_state::AppState,
    dns,
    extract::doh::{DNSMimeType, DNSRequestBody, DNSRequestQuery},
    traits::ServerSetup,
};

/// GET handler for resolving DoH queries
pub async fn get<S: ServerSetup>(
    State(state): State<AppState<S>>,
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
pub async fn post<S: ServerSetup>(
    State(state): State<AppState<S>>,
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
    use std::str::FromStr;

    use diesel::ExpressionMethods;
    use diesel_async::RunQueryDsl;
    use http::{Method, StatusCode};
    use mime::Mime;
    use rs_ucan::DefaultFact;
    use serde_json::json;
    use testresult::TestResult;

    use crate::{
        db::schema::{accounts, volumes},
        test_utils::{test_context::TestContext, RouteBuilder},
    };

    use pretty_assertions::assert_eq;

    #[test_log::test(tokio::test)]
    async fn test_dns_json_soa() -> TestResult {
        let ctx = TestContext::new().await;

        let (status, body) = RouteBuilder::<DefaultFact>::new(
            ctx.app(),
            Method::GET,
            format!("/dns-query?name={}&type={}", "fission.app", "soa"),
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
        );

        Ok(())
    }

    #[test_log::test(tokio::test)]
    async fn test_dns_json_gateway() -> TestResult {
        let ctx = TestContext::new().await;

        let (status, body) = RouteBuilder::<DefaultFact>::new(
            ctx.app(),
            Method::GET,
            format!("/dns-query?name={}&type={}", "gateway.fission.app", "any"),
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
                format_args!("_did.{}.fission.app", username),
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
                  "RD": false,
                  "RA": false,
                  "AD": false,
                  "CD": false,
                  "Question": [
                    {
                      "name": "_did.donnie.fission.app.",
                      "type": 16
                    }
                  ],
                  "Answer": [
                    {
                      "name": "_did.donnie.fission.app.",
                      "type": 16,
                      "TTL": 60,
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
                format_args!("_dnslink.{}.fission.app", username),
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
                  "Status": 3,
                  "TC": false,
                  "RD": false,
                  "RA": false,
                  "AD": false,
                  "CD": false,
                  "Question": [
                    {
                      "name": "_dnslink.donnie.fission.app.",
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

    #[test_log::test(tokio::test)]
    async fn test_dns_json_dnslink_volume_ok() -> TestResult {
        let ctx = TestContext::new().await;
        let mut conn = ctx.get_db_conn().await;

        let username = "donnie";
        let email = "donnie@example.com";
        let did = "did:28:06:42:12";
        let cid = "bafybeihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku";

        let volume_id = diesel::insert_into(volumes::table)
            .values(volumes::cid.eq(cid))
            .returning(volumes::id)
            .get_result::<i32>(&mut conn)
            .await?;

        diesel::insert_into(accounts::table)
            .values((
                accounts::username.eq(username),
                accounts::email.eq(email),
                accounts::did.eq(did),
                accounts::volume_id.eq(volume_id),
            ))
            .execute(&mut conn)
            .await?;

        let (status, body) = RouteBuilder::<DefaultFact>::new(
            ctx.app(),
            Method::GET,
            format!(
                "/dns-query?name={}&type={}",
                format_args!("_dnslink.{}.fission.app", username),
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
                  "RD": false,
                  "RA": false,
                  "AD": false,
                  "CD": false,
                  "Question": [
                    {
                      "name": "_dnslink.donnie.fission.app.",
                      "type": 16
                    }
                  ],
                  "Answer": [
                    {
                      "name": "_dnslink.donnie.fission.app.",
                      "type": 16,
                      "TTL": 60,
                      "data": "dnslink=/ipfs/bafybeihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku"
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
    async fn test_dns_json_dnslink_volume_err_not_found() -> TestResult {
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
                format_args!("_dnslink.{}.fission.app", username),
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
                  "Status": 3,
                  "TC": false,
                  "RD": false,
                  "RA": false,
                  "AD": false,
                  "CD": false,
                  "Question": [
                    {
                      "name": "_dnslink.donnie.fission.app.",
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
