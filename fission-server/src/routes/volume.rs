//! Volume routes

use std::sync::Arc;
use tokio::sync::Mutex;

use crate::{
    authority::Authority,
    db::{self, Pool},
    error::AppResult,
    models::{account::Account, volume::NewVolumeRecord},
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
        (status = 200, description = "Found volume", body=account::AccountRequest),
        (status = 400, description = "Invalid request", body=AppError),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal Server Error", body=AppError)
    )
)]

/// GET handler to retrieve account volume CID
pub async fn get_cid(
    State(pool): State<Pool>,
    authority: Authority,
    Path(username): Path<String>,
) -> AppResult<(StatusCode, Json<NewVolumeRecord>)> {
    let conn = Arc::new(Mutex::new(db::connect(&pool).await?));

    let account = Account::find_by_username(conn.clone(), Some(authority.ucan), username).await?;

    let volume = account.get_volume(conn.clone()).await?;
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
    State(pool): State<Pool>,
    authority: Authority,
    Path(username): Path<String>,
    Json(payload): Json<NewVolumeRecord>,
) -> AppResult<(StatusCode, Json<NewVolumeRecord>)> {
    let conn = Arc::new(Mutex::new(db::connect(&pool).await?));

    let account = Account::find_by_username(conn.clone(), Some(authority.ucan), username).await?;

    let volume = account.update_volume_cid(conn.clone(), payload.cid).await?;
    Ok((StatusCode::OK, Json(volume)))
}
