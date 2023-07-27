//! Healthcheck route.

use crate::{
    app_state::AppState,
    db::{self, MIGRATIONS},
    error::AppResult,
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
    use anyhow::Result;
    use diesel::ExpressionMethods;
    use diesel_async::RunQueryDsl;
    use http::{Method, StatusCode};

    use crate::{
        db::__diesel_schema_migrations,
        routes::health::HealthcheckResponse,
        test_utils::{test_context::TestContext, RouteBuilder},
    };

    #[tokio::test]
    async fn test_healthcheck_healthy() -> Result<()> {
        let ctx = TestContext::new().await;

        let (status, body) = RouteBuilder::new(ctx.app(), Method::GET, "/healthcheck")
            .into_json_response::<HealthcheckResponse>()
            .await?;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.database_connected, true);
        assert_eq!(body.database_up_to_date, Some(true));

        Ok(())
    }

    #[tokio::test]
    async fn test_healthcheck_db_unavailable() -> Result<()> {
        let ctx = TestContext::new().await;
        let app = ctx.app();

        // Drop the database
        drop(ctx);

        let (status, body) = RouteBuilder::new(app, Method::GET, "/healthcheck")
            .into_json_response::<HealthcheckResponse>()
            .await?;

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body.database_connected, false);
        assert_eq!(body.database_up_to_date, None);

        Ok(())
    }

    #[tokio::test]
    async fn test_healthcheck_db_out_of_date() -> Result<()> {
        let ctx = TestContext::new().await;
        let mut conn = ctx.get_db_conn().await;

        // Insert a new migration at the end of time
        diesel::insert_into(__diesel_schema_migrations::table)
            .values(__diesel_schema_migrations::version.eq("2239-09-30-desolation".to_string()))
            .execute(&mut conn)
            .await?;

        let (status, body) = RouteBuilder::new(ctx.app(), Method::GET, "/healthcheck")
            .into_json_response::<HealthcheckResponse>()
            .await?;

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body.database_connected, true);
        assert_eq!(body.database_up_to_date, Some(false));

        Ok(())
    }
}
