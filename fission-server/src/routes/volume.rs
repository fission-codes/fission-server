//! Volume routes

use crate::{
    authority::Authority,
    db::{self},
    error::AppResult,
    models::{account::Account, volume::NewVolumeRecord},
    router::AppState,
};
use axum::extract::{Json, Path, State};
use http::StatusCode;

#[utoipa::path(
    get,
    path = "/api/account/{username}/volume/cid",
    security(
        ("ucan_bearer" = []),
    ),
    responses(
        (status = 200, description = "Found volume", body=NewAccount),
        (status = 400, description = "Invalid request", body=AppError),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal Server Error", body=AppError)
    )
)]

/// GET handler to retrieve account volume CID
pub async fn get_cid(
    State(state): State<AppState>,
    authority: Authority,
    Path(username): Path<String>,
) -> AppResult<(StatusCode, Json<NewVolumeRecord>)> {
    let mut conn = db::connect(&state.db_pool).await?;
    let account = Account::find_by_username(&mut conn, Some(authority.ucan), username).await?;
    let volume = account.get_volume(&mut conn).await?;

    Ok((StatusCode::OK, Json(volume)))
}

#[utoipa::path(
    put,
    path = "/api/account/{username}/volume/cid",
    security(
        ("ucan_bearer" = []),
    ),
    responses(
        (status = 200, description = "Successfully updated Volume", body=NewVolume),
        (status = 400, description = "Invalid request", body=AppError),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal Server Error", body=AppError)
    )
)]

/// Handler to update the CID associated with an account's volume
pub async fn update_cid(
    State(state): State<AppState>,
    authority: Authority,
    Path(username): Path<String>,
    Json(payload): Json<NewVolumeRecord>,
) -> AppResult<(StatusCode, Json<NewVolumeRecord>)> {
    let mut conn = db::connect(&state.db_pool).await?;
    let account = Account::find_by_username(&mut conn, Some(authority.ucan), username).await?;
    let volume = account.update_volume_cid(&mut conn, payload.cid).await?;

    Ok((StatusCode::OK, Json(volume)))
}
