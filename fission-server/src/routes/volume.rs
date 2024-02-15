//! TODO docs

use crate::{
    app_state::AppState, authority::Authority, db, error::AppResult, extract::json::Json,
    models::account::AccountRecord, setups::ServerSetup,
};
use axum::extract::{BodyStream, Path, State};
use car_mirror::messages::PushResponse;
use cid::Cid;
use diesel_async::{scoped_futures::ScopedFutureExt, AsyncConnection};
use fission_core::capabilities::{did::Did, fission::FissionAbility};
use futures_util::TryStreamExt;
use http::StatusCode;
use std::str::FromStr;
use tokio_util::io::StreamReader;

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
    body: BodyStream,
) -> AppResult<(StatusCode, Json<PushResponse>)> {
    let cid = Cid::from_str(&cid_string)?;

    let Did(did) = authority
        .get_capability(&state, FissionAbility::AccountManage)
        .await?;

    let conn = &mut db::connect(&state.db_pool).await?;
    conn.transaction(|conn| {
        async move {
            let account = AccountRecord::find_by_did(conn, did).await?;

            let reader = StreamReader::new(
                body.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e)),
            );

            let response: PushResponse = car_mirror::common::block_receive_car_stream(
                cid,
                reader,
                &Default::default(),
                &state.blocks.store,
                &state.blocks.car_mirror_cache,
            )
            .await?
            .into();

            if response.indicates_finished() {
                account
                    .set_volume_cid(conn, &cid_string, &state.blocks.ipfs_db())
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
