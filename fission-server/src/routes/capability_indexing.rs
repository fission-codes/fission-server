//! Routes for the capability indexing endpoints

use axum::extract::State;
use diesel_async::{scoped_futures::ScopedFutureExt, AsyncConnection};
use fission_core::{
    capabilities::{did::Did, indexing::IndexingAbility},
    common::UcansResponse,
};
use http::StatusCode;

use crate::{
    app_state::AppState,
    authority::Authority,
    db,
    error::{AppError, AppResult},
    extract::json::Json,
    models::capability_indexing::find_ucans_for_audience,
    traits::ServerSetup,
};

/// Return capabilities for a given DID
#[utoipa::path(
    get,
    path = "/api/v0/capabilities",
    security(
        ("ucan_bearer" = []),
    ),
    responses(
        (status = 200, description = "Found account", body = UcansResponse),
        (status = 400, description = "Invalid request", body = AppError),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Not found"),
    )
)]
pub async fn get_capabilities<S: ServerSetup>(
    State(state): State<AppState<S>>,
    authority: Authority,
) -> AppResult<(StatusCode, Json<UcansResponse>)> {
    let Did(audience_needle) = authority.get_capability(IndexingAbility::Fetch)?;

    let conn = &mut db::connect(&state.db_pool).await?;
    conn.transaction(|conn| {
        async move {
            let ucans = find_ucans_for_audience(audience_needle, conn)
                .await
                .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, Some(e)))?;

            Ok((StatusCode::OK, Json(UcansResponse { ucans })))
        }
        .scope_boxed()
    })
    .await
}
