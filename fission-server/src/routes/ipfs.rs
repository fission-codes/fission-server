//! IPFS routes

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

use crate::{app_state::AppState, error::AppResult, traits::IpfsDatabase};

/// Render a list of IPFS node addresses
pub async fn peers<D: IpfsDatabase>(
    State(state): State<AppState<D>>,
) -> AppResult<(StatusCode, Response)> {
    let json = json!(state.ipfs_peers);
    Ok((StatusCode::OK, Json(json).into_response()))
}
