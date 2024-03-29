//! Authority extractor
//!
//! Todo: this should be extracted to a separate crate and made available as a generic Axum UCAN extractor.

use std::str::FromStr;

use anyhow::anyhow;
use axum::{
    async_trait,
    extract::{FromRequestParts, TypedHeader},
    headers::{authorization::Bearer, Authorization, Header, HeaderName},
    http::request::Parts,
    RequestPartsExt,
};

use http::{HeaderValue, StatusCode};
use rs_ucan::ucan::Ucan;
use serde::de::DeserializeOwned;
use serde_json::json;

// 🧬

use crate::{authority::Authority, error::AppError};
use fission_core::{
    authority,
    authority::Error::{InvalidUcan, MissingCredentials},
};

/////////////////
// UCAN header //
/////////////////

/// The `ucans` header
#[derive(Debug)]
pub struct UcansHeader(Vec<Ucan>);

impl Header for UcansHeader {
    fn name() -> &'static HeaderName {
        static UCAN_HEADER: HeaderName = HeaderName::from_static("ucans");
        static UCAN_HEADER_NAME: &HeaderName = &UCAN_HEADER;
        UCAN_HEADER_NAME
    }

    fn decode<'i, I>(header_values: &mut I) -> Result<UcansHeader, headers::Error>
    where
        I: Iterator<Item = &'i http::HeaderValue>,
    {
        let mut ucans = Vec::new();

        for header_value in header_values {
            let header_str = header_value.to_str().map_err(|_| {
                tracing::warn!("Got non-string ucan request header: {:?}", header_value);
                headers::Error::invalid()
            })?;

            for ucan_str in header_str.split(',') {
                let ucan_str = ucan_str.trim();
                if ucan_str.is_empty() {
                    // This can be the case, since `"".split(",").collect() == vec![""]`.
                    // Also catches cases where someone sets `ucans=,,<token>` or uses trailing commas.
                    // Per Postel's principle we're lenient in what we accept.
                    continue;
                }
                let ucan = Ucan::from_str(ucan_str).map_err(|e| {
                    tracing::warn!(?ucan_str, "Got invalid ucan in ucan request header: {e}");
                    headers::Error::invalid()
                })?;
                ucans.push(ucan);
            }
        }

        Ok(UcansHeader(ucans))
    }

    fn encode<E>(&self, values: &mut E)
    where
        E: Extend<HeaderValue>,
    {
        let header_str = self
            .0
            .iter()
            .map(|ucan| ucan.encode().expect("Failed to encode UCAN"))
            .collect::<Vec<_>>()
            .join(" ");

        let header_value = HeaderValue::from_str(&header_str)
            .expect("Encoded UCAN into invalid HTTP header characters");

        values.extend([header_value]);
    }
}

////////////
// TRAITS //
////////////

#[async_trait]
impl<S, F> FromRequestParts<S> for Authority<F>
where
    S: Send + Sync,
    F: Clone + DeserializeOwned,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        do_extract_authority(parts).await.map_err(|err| match err {
            authority::Error::InsufficientCapabilityScope { .. } => {
                AppError::new(StatusCode::FORBIDDEN, Some("Insufficient capability scope"))
            }
            authority::Error::InvalidUcan { reason } => AppError::new(
                StatusCode::UNAUTHORIZED,
                Some(format!("Invalid UCAN: {reason}")),
            ),
            authority::Error::MissingCredentials => {
                AppError::new(StatusCode::UNAUTHORIZED, Some("Missing credentials"))
            }
            authority::Error::MissingProofs { proofs_needed } => AppError::new(
                StatusCode::NOT_EXTENDED,
                Some(json!({ "prf": proofs_needed })),
            ),
        })
    }
}

async fn do_extract_authority<F: Clone + DeserializeOwned>(
    parts: &mut Parts,
) -> Result<Authority<F>, authority::Error> {
    // Extract the token from the authorization header
    let TypedHeader(Authorization(bearer)) = parts
        .extract::<TypedHeader<Authorization<Bearer>>>()
        .await
        .map_err(|e| {
            tracing::error!(?e, "Error while looking up bearer token header value");
            MissingCredentials
        })?;

    let TypedHeader(UcansHeader(proofs)) = parts
        .extract::<TypedHeader<UcansHeader>>()
        .await
        .map_err(|e| {
            tracing::error!(?e, "Error while looking up ucans header value");
            MissingCredentials
        })?;

    // Decode the UCAN
    let token = bearer.token();
    let ucan = Ucan::try_from(token).map_err(|reason| InvalidUcan {
        reason: anyhow!(reason),
    })?;

    // Construct authority
    Ok(Authority { ucan, proofs })
}

///////////
// TESTS //
///////////

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        app_state::AppState, setups::test::TestSetup, test_utils::test_context::TestContext,
    };
    use axum::{
        body::BoxBody,
        extract::State,
        routing::{get, Router},
    };
    use fission_core::ed_did_key::EdDidKey;
    use http::{Request, Response};
    use rs_ucan::builder::UcanBuilder;
    use testresult::TestResult;
    use tower::ServiceExt;

    #[test_log::test(tokio::test)]
    async fn extract_authority() -> TestResult {
        let ctx = &TestContext::new().await?;
        let issuer = &EdDidKey::generate();

        // Test if request requires a valid UCAN
        async fn authorized_get(
            _state: State<AppState<TestSetup>>,
            _authority: Authority,
        ) -> Response<BoxBody> {
            Response::default()
        }

        let app: Router = Router::new()
            .route("/", get(authorized_get))
            .with_state(ctx.app_state().clone());

        // If a valid UCAN is given
        let ucan: Ucan = UcanBuilder::default()
            .for_audience(ctx.server_did())
            .with_lifetime(100)
            .sign(issuer)?;

        let ucan_string: String = ucan.encode()?;
        let authed = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("Authorization", format!("Bearer {}", ucan_string))
                    .body("".into())?,
            )
            .await?;

        assert_eq!(authed.status(), StatusCode::OK);

        Ok(())
    }

    #[test_log::test(tokio::test)]
    async fn extract_authority_no_auth_header() -> TestResult {
        let ctx = &TestContext::new().await?;

        // Test if request requires a valid UCAN
        async fn authorized_get(
            _state: State<AppState<TestSetup>>,
            _authority: Authority,
        ) -> Response<BoxBody> {
            Response::default()
        }

        let app: Router = Router::new()
            .route("/", get(authorized_get))
            .with_state(ctx.app_state().clone());

        // If no authorization header is provided
        let not_authed = app
            .oneshot(Request::builder().uri("/").body("".into()).unwrap())
            .await?;

        assert_eq!(not_authed.status(), StatusCode::UNAUTHORIZED);

        Ok(())
    }
}
