//! IPFS routes

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

use crate::{
    error::{AppError, AppResult},
    settings::Settings,
};

use tracing::log;

/// Render a list of IPFS node addresses
pub async fn peers() -> AppResult<(StatusCode, Response)> {
    let settings = Settings::load();
    if let Err(error) = settings {
        log::error!("Failed to load settings: {}", error);
        return Err(AppError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            Some("Internal Server Error."),
        ));
    }

    let json = json!(settings.unwrap().ipfs().peers);

    Ok((StatusCode::OK, Json(json).into_response()))
}
