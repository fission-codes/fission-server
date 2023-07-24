//! Healthcheck route.

use crate::{
    db::{self, MIGRATIONS},
    error::AppResult,
    router::AppState,
};
use axum::{self, extract::State, http::StatusCode};
use diesel::{
    migration::{Migration, MigrationSource},
    pg::Pg,
};
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
                .map(|version| version == latest_embedded_migration_version())
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

fn latest_embedded_migration_version() -> Option<String> {
    if let Some(migration) = MIGRATIONS.migrations().unwrap().iter().last() {
        let version = <dyn Migration<Pg> as Migration<Pg>>::name(migration)
            .version()
            .to_string();

        Some(version)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use axum::{body::Body, http::Request};
    use diesel::ExpressionMethods;
    use diesel_async::RunQueryDsl;
    use http::StatusCode;
    use tower::ServiceExt;

    use crate::{
        db::__diesel_schema_migrations,
        router::{setup_app_router, AppState},
        test_utils::test_context::TestContext,
    };

    #[tokio::test]
    async fn test_healthcheck_healthy() {
        let ctx = TestContext::new();
        let app_state = AppState {
            db_pool: ctx.pool().await,
        };

        let app = setup_app_router(app_state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/healthcheck")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_healthcheck_db_unavailable() {
        let ctx = TestContext::new();
        let app_state = AppState {
            db_pool: ctx.pool().await,
        };

        // Drop the database
        drop(ctx);

        let app = setup_app_router(app_state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/healthcheck")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn test_healthcheck_db_out_of_date() {
        let ctx = TestContext::new();
        let app_state = AppState {
            db_pool: ctx.pool().await,
        };

        let mut conn = app_state.db_pool.get().await.unwrap();

        // Insert a new migration at the end of time
        diesel::insert_into(__diesel_schema_migrations::table)
            .values(__diesel_schema_migrations::version.eq("2239-09-30-desolation".to_string()))
            .execute(&mut conn)
            .await
            .unwrap();

        let app = setup_app_router(app_state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/healthcheck")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
