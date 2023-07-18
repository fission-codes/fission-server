//! Healthcheck route.

use crate::{
    db::{self},
    error::AppResult,
    router::AppState,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    database_up_to_date: Option<bool>,
}

impl HealthcheckResponse {
    /// Whether the service is healthy
    pub fn is_healthy(&self) -> bool {
        self.database_connected && self.database_up_to_date.unwrap_or_default()
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
    State(state): State<AppState>,
) -> AppResult<(StatusCode, axum::Json<serde_json::Value>)> {
    let (database_connected, database_up_to_date) =
        if let Ok(mut conn) = db::connect(&state.db_pool).await {
            let database_connected = conn.ping().await.is_ok();
            let database_up_to_date = db::schema_version(&mut conn)
                .await
                .map(|version| version == state.db_version)
                .ok();

            (database_connected, database_up_to_date)
        } else {
            (false, None)
        };

    let response = HealthcheckResponse {
        database_connected,
        database_up_to_date,
    };

    Ok((response.status_code(), axum::Json(json! { response})))
}
