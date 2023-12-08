//! Generic ping route.

use crate::error::AppResult;
use axum::{self, http::StatusCode};

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
    use http::{Method, StatusCode};
    use rs_ucan::DefaultFact;
    use testresult::TestResult;

    use crate::test_utils::{route_builder::RouteBuilder, test_context::TestContext};

    #[test_log::test(tokio::test)]
    async fn test_ping() -> TestResult {
        let ctx = TestContext::new().await;

        let (status, _) = RouteBuilder::<DefaultFact>::new(ctx.app(), Method::GET, "/ping")
            .into_raw_response()
            .await?;

        assert_eq!(status, StatusCode::OK);

        Ok(())
    }
}
