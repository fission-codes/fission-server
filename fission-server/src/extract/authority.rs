//! Authority extractor

use axum::{
    async_trait,
    extract::{FromRequestParts, TypedHeader},
    headers::{authorization::Bearer, Authorization},
    http::request::Parts,
    RequestPartsExt,
};

use ucan::ucan::Ucan;

// 🧬

use crate::authority::Authority;
use fission_common::{
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
    type Rejection = authority::Error;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Extract the token from the authorization header
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| MissingCredentials)?;

        // Decode the UCAN
        let token = bearer.token();
        let ucan = Ucan::try_from(token).map_err(|err| InvalidUcan {
            reason: err.to_string(),
        })?;

        // Fin
        Ok(Authority { ucan: ucan })
    }
}
