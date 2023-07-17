//! Healthcheck route.

use crate::{
    db::{self, Pool},
    error::AppResult,
};
use axum::{self, extract::State, http::StatusCode};
use diesel_async::pooled_connection::PoolableConnection;
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::ToSchema;

/// A healthcheck response containing diagnostic information for the service
#[derive(ToSchema, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct HealthcheckResponse {
    database_connected: bool,
}

impl HealthcheckResponse {
    /// Whether the service is healthy
    pub fn is_healthy(&self) -> bool {
        self.database_connected
    }

    /// The status code for the healthcheck response
    pub fn status_code(&self) -> StatusCode {
        if self.is_healthy() {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        }
    }
}

/// GET handler for checking service health.
#[utoipa::path(
    get,
    path = "/healthcheck",
    responses(
        (status = 200, description = "fission-server healthy", body=HealthcheckResponse),
        (status = 503, description = "fission-server not healthy", body=HealthcheckResponse)
    )
)]
pub async fn healthcheck(
    State(pool): State<Pool>,
) -> AppResult<(StatusCode, axum::Json<serde_json::Value>)> {
    let database_connected = db::connect(&pool)
        .await
        .map(move |mut conn| async move { conn.ping().await.ok() })
        .is_ok();

    let response = HealthcheckResponse { database_connected };

    Ok((response.status_code(), axum::Json(json! { response})))
}
