//! TODO docs

use crate::{
    app_state::AppState, authority::Authority, db, error::AppResult, extract::json::Json,
    models::account::AccountRecord, setups::ServerSetup,
};
use axum::extract::{Path, State};
use bytes::Bytes;
use car_mirror::{common::CarFile, messages::PushResponse};
use cid::Cid;
use diesel_async::{scoped_futures::ScopedFutureExt, AsyncConnection};
use fission_core::capabilities::{did::Did, fission::FissionAbility};
use http::StatusCode;
use std::str::FromStr;

/// PUT uploading a new volume CID
#[utoipa::path(
    put,
    path = "/api/v0/volume/cid/:cid",
    // request_body = Bytes,
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
    body: Bytes,
) -> AppResult<(StatusCode, Json<PushResponse>)> {
    let cid = Cid::from_str(&cid_string)?;

    let Did(did) = authority
        .get_capability(&state, FissionAbility::AccountManage)
        .await?;

    let conn = &mut db::connect(&state.db_pool).await?;
    conn.transaction(|conn| {
        async move {
            let account = AccountRecord::find_by_did(conn, did).await?;

            let response = car_mirror::push::response(
                cid,
                CarFile { bytes: body },
                &Default::default(),
                &state.blocks.clone(),
                &state.blocks.car_mirror_cache,
            )
            .await?;

            if response.indicates_finished() {
                account
                    .set_volume_cid(conn, &cid_string, &state.blocks.ipfs_db)
                    .await?;

                Ok((StatusCode::OK, Json(response)))
            } else {
                Ok((StatusCode::ACCEPTED, Json(response)))
            }
        }
        .scope_boxed()
    })
    .await
}
