//! Authority extractor
//! 
//! Todo: this should be extracted to a separate crate and made available as a generic Axum UCAN extractor.

use axum::{
    async_trait,
    extract::{FromRequestParts, TypedHeader, self},
    headers::{authorization::Bearer, Authorization, HeaderName, Header},
    http::request::Parts,
    RequestPartsExt,
};

use http::StatusCode;
use serde_json::json;
use tracing::log;
use ucan::ucan::Ucan;

// 🧬

use crate::{authority::Authority, error::AppError};
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

    fn decode<'i, I>(values: &mut I) -> Result<UcanHeader, axum::headers::Error>
    where
        I: Iterator<Item = &'i http::HeaderValue>,
    {
        let mut ucans = Vec::<Ucan>::new();

        let mut c = 0;

        let ucans = values.map(|val| {
            c += 1;

            if let Ok(header_str) = val.to_str() {
                if let Some((_, token_str)) = header_str.split_once(" ") {
                    if let Ok(ucan) = Ucan::try_from(token_str) {
                        return Some(ucan)
                    }
                }
            }

            None
        });

        let valid_headers: Vec<Ucan> = ucans.filter_map(|u| u).collect();

        if valid_headers.len() != c {
            Err(axum::headers::Error::invalid())
        } else {
            Ok(Self(valid_headers))
        }

    }

    // Unimplemented!
    // FIXME
    fn encode<E>(&self, values: &mut E)
    where
        E: Extend<http::HeaderValue>,
    {
        // for ucan in &self.0 {
        // }
        ()
    }
}

////////////
// TRAITS //
////////////

#[async_trait]
impl<S> FromRequestParts<S> for Authority
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        do_extract_authority(parts).await.map_err(|err| match err {
            authority::Error::InsufficientCapabilityScope { .. } => {
                AppError::new(StatusCode::FORBIDDEN, Some("Insufficient capability scope"))
            }
            authority::Error::InvalidUcan { reason } => AppError::new(
                StatusCode::UNAUTHORIZED,
                Some(format!("Invalid UCAN: {}", reason)),
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

async fn do_extract_authority(parts: &mut Parts) -> Result<Authority, authority::Error> {
    // Extract the token from the authorization header
    let TypedHeader(Authorization(bearer)) = parts
        .extract::<TypedHeader<Authorization<Bearer>>>()
        .await
        .map_err(|_| MissingCredentials)?;

    let TypedHeader(UcanHeader(proofs)) = parts
        .extract::<TypedHeader<UcanHeader>>()
        .await
        .map_err(|_| MissingCredentials)?;

    println!("parts: {:?}", parts);
    println!("proofs: {:?}", proofs);

    // Decode the UCAN
    let token = bearer.token();
    let ucan = Ucan::try_from(token).map_err(|err| {
        log::error!("Error decoding UCAN: {}", err);
        InvalidUcan {
            reason: err.to_string(),
        }
    })?;

    // Construct authority
    let authority = Authority { ucan, proofs };

    // Validate the authority
    authority
        .validate()
        .await
        .map(|_| authority)
        .map_err(|reason| InvalidUcan { reason })
}

///////////
// TESTS //
///////////

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        http::StatusCode,
        routing::{get, Router},
    };
    use fission_core::authority::key_material::{generate_ed25519_material, SERVER_DID};
    use http::Request;
    use tower::ServiceExt;
    use ucan::builder::UcanBuilder;

    #[tokio::test]
    async fn extract_authority() {
        let issuer = generate_ed25519_material();

        // Test if request requires a valid UCAN
        let app: Router<(), axum::body::Body> = Router::new().route(
            "/",
            get(|_authority: Authority| async { axum::body::Empty::new() }),
        );

        // If a valid UCAN is given
        let ucan = UcanBuilder::default()
            .issued_by(&issuer)
            .for_audience(SERVER_DID)
            .with_lifetime(100)
            .build()
            .unwrap()
            .sign()
            .await
            .unwrap();

        let ucan_string: String = Ucan::encode(&ucan).unwrap();
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
        let issuer = generate_ed25519_material();

        // Test if request requires a valid UCAN
        let app: Router<(), axum::body::Body> = Router::new().route(
            "/",
            get(|_authority: Authority| async { axum::body::Empty::new() }),
        );

        // If an invalid UCAN is given
        let faulty_ucan = UcanBuilder::default()
            .issued_by(&issuer)
            .for_audience(SERVER_DID)
            .with_expiration(0)
            .build()
            .unwrap()
            .sign()
            .await
            .unwrap();

        let faulty_ucan_string: String = Ucan::encode(&faulty_ucan).unwrap();
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
