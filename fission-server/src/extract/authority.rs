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

use crate::{
    authority::{did_verifier_map, Authority},
    error::AppError,
};
use fission_core::{
    authority,
    authority::Error::{InvalidUcan, MissingCredentials},
};

/////////////////
// UCAN header //
/////////////////

struct UcanHeader(Vec<Ucan>);

impl Header for UcanHeader {
    fn name() -> &'static HeaderName {
        static UCAN_HEADER: HeaderName = HeaderName::from_static("ucan");
        static UCAN_HEADER_NAME: &HeaderName = &UCAN_HEADER;
        UCAN_HEADER_NAME
    }

    fn decode<'i, I>(header_values: &mut I) -> Result<UcanHeader, headers::Error>
    where
        I: Iterator<Item = &'i http::HeaderValue>,
    {
        let mut ucans = Vec::new();

        for header_value in header_values {
            let header_str = header_value.to_str().map_err(|_| {
                tracing::warn!("Got non-string ucan request header: {:?}", header_value);
                headers::Error::invalid()
            })?;

            for ucan_str in header_str.split_ascii_whitespace() {
                let ucan = Ucan::from_str(ucan_str).map_err(|e| {
                    tracing::warn!("Got invalid ucan in ucan request header: {e}");
                    headers::Error::invalid()
                })?;
                ucans.push(ucan);
            }
        }

        Ok(UcanHeader(ucans))
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
        .map_err(|_| MissingCredentials)?;

    let TypedHeader(UcanHeader(proofs)) = parts
        .extract::<TypedHeader<UcanHeader>>()
        .await
        .map_err(|_| MissingCredentials)?;

    // Decode the UCAN
    let token = bearer.token();
    let ucan = Ucan::try_from(token).map_err(|reason| InvalidUcan {
        reason: anyhow!(reason),
    })?;

    // Construct authority
    let authority = Authority { ucan, proofs };

    // Validate the authority
    authority
        .validate(&did_verifier_map())
        .map_err(|reason| InvalidUcan { reason })?;

    Ok(authority)
}

///////////
// TESTS //
///////////

#[cfg(test)]
mod tests {
    use crate::authority::generate_ed25519_issuer;

    use super::*;
    use axum::{
        body::BoxBody,
        http::StatusCode,
        routing::{get, Router},
    };
    use http::{Request, Response};
    use rs_ucan::builder::UcanBuilder;
    use tower::ServiceExt;

    #[tokio::test]
    async fn extract_authority() {
        let (issuer, key) = generate_ed25519_issuer();

        // Test if request requires a valid UCAN
        async fn authorized_get(_authority: Authority) -> Response<BoxBody> {
            Response::default()
        }
        let app: Router = Router::new().route("/", get(authorized_get));

        // If a valid UCAN is given
        let ucan: Ucan = UcanBuilder::default()
            .issued_by(issuer)
            .for_audience("did:web:runfission.com")
            .with_lifetime(100)
            .sign(&key)
            .unwrap();

        let ucan_string: String = ucan.encode().unwrap();
        let authed = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("Authorization", format!("Bearer {}", ucan_string))
                    .body("".into())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(authed.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn extract_authority_invalid_ucan() {
        let (issuer, key) = generate_ed25519_issuer();

        // Test if request requires a valid UCAN
        let app: Router<(), axum::body::Body> = Router::new().route(
            "/",
            get(|_authority: Authority| async { axum::body::Empty::new() }),
        );

        // If an invalid UCAN is given
        let faulty_ucan: Ucan = UcanBuilder::default()
            .issued_by(issuer)
            .for_audience("did:web:runfission.com")
            .with_expiration(0)
            .sign(&key)
            .unwrap();

        let faulty_ucan_string: String = faulty_ucan.encode().unwrap();
        let invalid_auth = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("Authorization", format!("Bearer {}", faulty_ucan_string))
                    .body("".into())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(invalid_auth.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn extract_authority_no_auth_header() {
        // Test if request requires a valid UCAN
        let app: Router<(), axum::body::Body> = Router::new().route(
            "/",
            get(|_authority: Authority| async { axum::body::Empty::new() }),
        );

        // If no authorization header is provided
        let not_authed = app
            .oneshot(Request::builder().uri("/").body("".into()).unwrap())
            .await
            .unwrap();

        assert_eq!(not_authed.status(), StatusCode::UNAUTHORIZED);
    }
}
