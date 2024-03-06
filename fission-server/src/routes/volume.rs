//! Routes for volume uploads and downloads using car-mirror

use crate::{
    app_state::AppState,
    authority::Authority,
    db,
    error::{AppError, AppResult},
    extract::json::Json,
    models::account::AccountRecord,
    setups::ServerSetup,
};
use axum::{
    body::StreamBody,
    extract::{BodyStream, Path, State},
};
use bytes::Bytes;
use car_mirror::messages::{PullRequest, PushResponse};
use cid::Cid;
use diesel_async::{scoped_futures::ScopedFutureExt, AsyncConnection};
use fission_core::capabilities::{did::Did, fission::FissionAbility};
use futures_util::{Stream, TryStreamExt};
use http::StatusCode;
use std::str::FromStr;
use tokio_util::io::StreamReader;

/// PUT uploading a new volume CID
#[utoipa::path(
    put,
    path = "/api/v0/volume/cid/:cid",
    request_body = BodyStream,
    security(
        ("ucan_bearer" = []),
    ),
    responses(
        (status = 200, description = "Successfully uploaded data"),
        (status = 202, description = "Data partially uploaded"),
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

            let response = car_mirror::push::response_streaming(
                cid,
                reader,
                &Default::default(),
                &state.blocks.store,
                &state.blocks.cache,
            )
            .await?;

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

/// GET some data via car-mirror
#[utoipa::path(
    get,
    path = "/api/v0/volume/cid/:cid",
    responses(
        (status = 200, description = "Ok"),
        (status = 400, description = "Bad Request"),
    )
)]
pub async fn get_volume_cid<S: ServerSetup>(
    State(state): State<AppState<S>>,
    Path(cid_string): Path<String>,
    Json(request): Json<PullRequest>,
) -> AppResult<(StatusCode, StreamBody<impl Stream<Item = AppResult<Bytes>>>)> {
    let cid = Cid::from_str(&cid_string)?;

    let car_stream = car_mirror::pull::response_streaming(
        cid,
        request,
        state.blocks.store.clone(),
        state.blocks.cache.clone(),
    )
    .await?;

    Ok((
        StatusCode::OK,
        StreamBody::new(car_stream.map_err(AppError::from)),
    ))
}
