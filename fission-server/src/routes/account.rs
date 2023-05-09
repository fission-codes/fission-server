//! Generic ping route.

use crate::error::AppResult;
use axum::{self, http::StatusCode};

/// POST handler for creating a new account
// #[utoipa::path(
//     get,
//     path = "/ping",
//     responses(
//         (status = 200, description = "Ping successful"),
//         (status = 500, description = "Ping not successful", body=AppError)
//     )
// )]

pub async fn create(_authority: crate::authority::Authority) -> AppResult<StatusCode> {
    // TODO:
    // Use issuer from `authority.ucan`

    Ok(StatusCode::OK)
}
