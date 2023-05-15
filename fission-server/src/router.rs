//! Main [axum::Router] interface for webserver.

use crate::{
    db::connection::Pool,
    middleware::logging::{log_request_response, DebugOnlyLogger, Logger},
    routes::{fallback::notfound_404, health, ping},
};
use axum::{routing::get, Router};

/// Setup main router for application.
pub fn setup_app_router(db_pool: Pool) -> Router {
    let mut router = Router::new()
        .route("/ping", get(ping::get))
        .fallback(notfound_404)
        .with_state(db_pool);

    // Logging layer
    router = router.layer(axum::middleware::from_fn(log_request_response::<Logger>));

    // Healthcheck layer
    let mut healthcheck_router = Router::new().route("/healthcheck", get(health::healthcheck));

    healthcheck_router = healthcheck_router.layer(axum::middleware::from_fn(
        log_request_response::<DebugOnlyLogger>,
    ));

    Router::merge(router, healthcheck_router)
}
