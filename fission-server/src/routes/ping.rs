//! Generic ping route.

use crate::error::AppResult;
use axum::http::StatusCode;

/// GET handler for internal pings and availability
#[utoipa::path(
    get,
    path = "/ping",
    responses(
        (status = 200, description = "Ping successful"),
    )
)]

pub async fn get() -> AppResult<StatusCode> {
    Ok(StatusCode::OK)
}

#[cfg(test)]
mod tests {
    use crate::test_utils::test_context::TestContext;
    use http::{Method, StatusCode};
    use testresult::TestResult;

    #[test_log::test(tokio::test)]
    async fn test_ping() -> TestResult {
        let ctx = &TestContext::new().await?;

        let (status, _) = ctx
            .request(Method::GET, "/ping")
            .into_raw_response()
            .await?;

        assert_eq!(status, StatusCode::OK);

        Ok(())
    }
}
