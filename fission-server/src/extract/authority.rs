//! Authority extractor

use axum::{
    async_trait,
    extract::{FromRequestParts, TypedHeader},
    headers::{authorization::Bearer, Authorization},
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

    // Decode the UCAN
    let token = bearer.token();
    let ucan = Ucan::try_from(token).map_err(|err| {
        log::error!("Error decoding UCAN: {}", err);
        InvalidUcan {
            reason: err.to_string(),
        }
    })?;

    // Construct authority
    let authority = Authority { ucan };

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

        // If no authorization header is provided
        let not_authed = app
            .oneshot(Request::builder().uri("/").body("".into()).unwrap())
            .await
            .unwrap();

        assert_eq!(not_authed.status(), StatusCode::UNAUTHORIZED);
    }
}
