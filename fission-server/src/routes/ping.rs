//! Generic ping route.

use crate::error::AppResult;
use axum::{self, http::StatusCode};
use ucan::ucan::Ucan;

/// GET handler for internal pings and availability
#[utoipa::path(
    get,
    path = "/ping",
    responses(
        (status = 200, description = "Ping successful"),
        (status = 500, description = "Ping not successful", body=AppError)
    )
)]

pub async fn get(ucan: Ucan) -> AppResult<(StatusCode, String)> {
    let ucan_string = Ucan::encode(&ucan)?;
    let response = format!("Authed successfully!\n{}", ucan_string);
    Ok((StatusCode::OK, response))
}
