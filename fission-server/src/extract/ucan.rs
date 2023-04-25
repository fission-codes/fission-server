use axum::{
    async_trait,
    extract::{FromRequestParts, TypedHeader},
    headers::{authorization::Bearer, Authorization},
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Response},
    Json, RequestPartsExt,
};

use serde_json::json;
use ucan::ucan::Ucan;

use crate::authority::Authority;

///////////
// TYPES //
///////////

#[derive(Debug)]
enum AuthError {
    MissingCredentials,
    InvalidToken,
}

////////////
// TRAITS //
////////////

#[async_trait]
impl<S> FromRequestParts<S> for Authority
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        // Extract the token from the authorization header
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| AuthError::MissingCredentials)?;

        // Decode the UCAN
        let token = bearer.token();
        let ucan = Ucan::try_from(token).map_err(|_| AuthError::InvalidToken)?;

        // Fin
        Ok(Authority { proof: ucan })
    }
}

/////////////////////
// IMPLEMENTATIONS //
/////////////////////

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AuthError::MissingCredentials => (StatusCode::BAD_REQUEST, "Missing credentials"),
            AuthError::InvalidToken => (StatusCode::BAD_REQUEST, "Invalid UCAN"),
        };
        let body = Json(json!({
            "error": error_message,
        }));
        (status, body).into_response()
    }
}
