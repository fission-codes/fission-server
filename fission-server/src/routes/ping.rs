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
    use axum::{body::Body, http::Request};
    use http::StatusCode;
    use tower::ServiceExt;

    use crate::test_utils::test_context::TestContext;

    #[tokio::test]
    async fn test_ping() {
        let ctx = TestContext::new().await;

        let response = ctx
            .app()
            .oneshot(Request::builder().uri("/ping").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}
