//! Generic ping route.

use crate::error::AppResult;
use axum::{self, http::StatusCode};

/// GET handler for internal pings and availability
#[utoipa::path(
    get,
    path = "/ping",
    responses(
        (status = 200, description = "Ping successful"),
        (status = 500, description = "Ping not successful", body=AppError)
    )
)]

pub async fn get() -> AppResult<StatusCode> {
    Ok(StatusCode::OK)
}

#[cfg(test)]
mod tests {
    use http::{Method, StatusCode};

    use crate::test_utils::{test_context::TestContext, RouteBuilder};

    #[tokio::test]
    async fn test_ping() {
        let ctx = TestContext::new().await;

        let (status, _) = RouteBuilder::new(ctx.app(), Method::GET, "/ping")
            .into_raw_response()
            .await
            .unwrap();

        assert_eq!(status, StatusCode::OK);
    }
}
