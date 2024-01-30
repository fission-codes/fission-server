//! TODO docs

use crate::{
    app_state::AppState, authority::Authority, db, error::AppResult,
    models::account::AccountRecord, setups::ServerSetup,
};
use axum::extract::{Path, State};
use diesel_async::{scoped_futures::ScopedFutureExt, AsyncConnection};
use fission_core::capabilities::{did::Did, fission::FissionAbility};
use http::StatusCode;

/// PUT uploading a new volume CID
#[utoipa::path(
    put,
    path = "/api/v0/volume/cid/:cid",
    // request_body = AccountCreationRequest,
    security(
        ("ucan_bearer" = []),
    ),
    responses(
        (status = 201, description = "Successfully uploaded data"),
        (status = 400, description = "Bad Request"),
        (status = 403, description = "Forbidden"),
    )
)]
pub async fn put_volume_cid<S: ServerSetup>(
    State(state): State<AppState<S>>,
    authority: Authority,
    Path(cid_string): Path<String>,
) -> AppResult<(StatusCode, ())> {
    let Did(did) = authority
        .get_capability(&state, FissionAbility::AccountManage)
        .await?;

    let conn = &mut db::connect(&state.db_pool).await?;
    conn.transaction(|conn| {
        async move {
            AccountRecord::find_by_did(conn, did)
                .await?
                .set_volume_cid(conn, &cid_string, &state.ipfs_db)
                .await?;

            Ok((StatusCode::OK, ()))
        }
        .scope_boxed()
    })
    .await
}
