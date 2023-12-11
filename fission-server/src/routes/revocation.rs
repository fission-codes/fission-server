//! Routes for UCAN revocation

use crate::{
    app_state::AppState,
    authority::Authority,
    db,
    error::{AppError, AppResult},
    extract::json::Json,
    models::revocation::NewRevocationRecord,
    setups::ServerSetup,
};
use axum::extract::State;
use fission_core::{common::SuccessResponse, revocation::Revocation};
use http::StatusCode;

/// POST handler for adding a UCAN revocation
#[utoipa::path(
    post,
    path = "/api/v0/revocations",
    request_body = Revocation,
    security(
        ("ucan_bearer" = []),
    ),
    responses(
        (status = 201, description = "Successfully revoked UCAN", body = SuccessResponse),
        (status = 400, description = "Bad Request"),
        (status = 403, description = "Forbidden"),
    )
)]
pub async fn post_revocation<S: ServerSetup>(
    State(state): State<AppState<S>>,
    authority: Authority,
    Json(revocation): Json<Revocation>,
) -> AppResult<(StatusCode, Json<SuccessResponse>)> {
    authority
        .validate_revocation(&revocation)
        .map_err(|e| AppError::new(StatusCode::FORBIDDEN, Some(e)))?;

    let conn = &mut db::connect(&state.db_pool).await?;
    NewRevocationRecord::new(revocation).insert(conn).await?;

    Ok((StatusCode::CREATED, Json(SuccessResponse { success: true })))
}
