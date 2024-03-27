//! Routes for volume uploads and downloads using car-mirror

use crate::{
    app_state::AppState,
    authority::Authority,
    db,
    error::{AppError, AppResult},
    extract::dag_cbor::DagCbor,
    models::account::AccountRecord,
    setups::ServerSetup,
};
use axum::{
    body::StreamBody,
    extract::{BodyStream, Path, State},
    TypedHeader,
};
use bytes::Bytes;
use car_mirror::messages::{PullRequest, PushResponse};
use cid::Cid;
use diesel_async::{scoped_futures::ScopedFutureExt, AsyncConnection};
use fission_core::{
    capabilities::did::Did,
    caps::{CmdAccountManage, FissionAbility},
};
use futures_util::{Stream, TryStreamExt};
use headers::ContentLength;
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
pub async fn push_volume_cid<S: ServerSetup>(
    State(state): State<AppState<S>>,
    authority: Authority,
    Path(cid_string): Path<String>,
    content_length_header: Option<TypedHeader<ContentLength>>,
    body: BodyStream,
) -> AppResult<(StatusCode, DagCbor<PushResponse>)> {
    let cid = Cid::from_str(&cid_string)?;
    let content_length = content_length_header.map(|TypedHeader(ContentLength(len))| len);

    tracing::info!(content_length, "Parsed content length hint");

    let Did(did) = authority
        .get_capability(&state, FissionAbility::AccountManage(CmdAccountManage))
        .await?;

    let conn = &mut db::connect(&state.db_pool).await?;
    conn.transaction(|conn| {
        async move {
            let account = AccountRecord::find_by_did(conn, did).await?;

            let mut reader = StreamReader::new(
                body.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e)),
            );

            let response = car_mirror::push::response_streaming(
                cid,
                &mut reader,
                &Default::default(),
                &state.blocks.store,
                &state.blocks.cache,
            )
            .await?;

            if content_length.is_some() {
                tracing::info!("Draining request body");
                // If the client provided a `Content-Length` value, then
                // we know the client didn't stream the request.
                // In that case, it's common that the client doesn't support
                // getting a response before it finished finished sending,
                // because the socket closes early, before the client manages
                // to read the response.
                tokio::io::copy(&mut reader, &mut tokio::io::sink()).await?;
            }

            if response.indicates_finished() {
                account
                    .set_volume_cid(conn, &cid_string, &state.blocks.ipfs_db())
                    .await?;

                Ok((StatusCode::OK, DagCbor(response)))
            } else {
                Ok((StatusCode::ACCEPTED, DagCbor(response)))
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
pub async fn pull_volume_cid<S: ServerSetup>(
    State(state): State<AppState<S>>,
    Path(cid_string): Path<String>,
    request: Option<DagCbor<PullRequest>>,
) -> AppResult<(StatusCode, StreamBody<impl Stream<Item = AppResult<Bytes>>>)> {
    let cid = Cid::from_str(&cid_string)?;

    let DagCbor(request) = request.unwrap_or_else(|| {
        DagCbor(PullRequest {
            resources: vec![cid],
            bloom_hash_count: 3,
            bloom_bytes: vec![],
        })
    });

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
