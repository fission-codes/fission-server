//! Volume routes

use crate::{error::AppResult, router::AppState};
use axum::{
    self,
    extract::{Json, Path, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};

use utoipa::ToSchema;

/// Volume Struct
#[derive(Deserialize, Serialize, Clone, Debug, ToSchema)]
pub struct Volume {
    cid: String,
}

impl Volume {
    /// Create a new instance of [Volume]
    pub fn new(cid: String) -> Self {
        Self { cid }
    }
}

#[utoipa::path(
    get,
    path = "/api/account/{name}/volume",
    responses(
        (status = 200, description = "Volume Found", body=Volume),
        (status = 400, description = "Invalid request", body=Response),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal Server Error", body=AppError)
    )
)]
/// GET handler for retreiving a volume CID
pub async fn get_cid(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> AppResult<(StatusCode, Json<Volume>)> {
    let volumes = state.volumes.read().await;
    let volume = volumes.get(&name).unwrap();
    Ok((StatusCode::OK, Json(volume.clone())))
}

#[utoipa::path(
    put,
    path = "/api/account/{name}/volume",
    request_body = Volume,
    responses(
        (status = 200, description = "Updated Volume CID", body=Volume),
        (status = 400, description = "Invalid request", body=Response),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal Server Error", body=AppError)
    )
)]
/// PUT handler for updating a volume CID
pub async fn update_cid(
    Path(name): Path<String>,
    Json(payload): Json<Volume>,
    State(state): State<AppState>,
) -> AppResult<(StatusCode, Json<Volume>)> {
    let mut volumes = state.volumes.write().await;
    let volume = volumes.get_mut(&name).unwrap();
    volume.cid = payload.cid.clone();
    Ok((StatusCode::OK, Json(volume.clone())))
}
