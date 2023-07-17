//! Main [axum::Router] interface for webserver.

use crate::{
    db::connection::Pool,
    middleware::logging::{log_request_response, DebugOnlyLogger, Logger},
    routes::{account, auth, fallback::notfound_404, health, ping},
};
use axum::{
    routing::{get, post},
    Router,
};

#[derive(Clone, Debug)]
/// Global application route state.
pub struct AppState {
    /// The database pool
    pub db_pool: Pool,
    /// The version of the latest database migration at time of application start
    pub db_version: String,
}

/// Setup main router for application.
pub fn setup_app_router(app_state: AppState) -> Router {
    let mut router = Router::new()
        .route("/ping", get(ping::get))
        .fallback(notfound_404)
        .with_state(app_state.clone());

    let api_router = Router::new()
        .route("/auth/email/verify", post(auth::request_token))
        .route("/account", post(account::create_account))
        .route("/account/:name", get(account::get_account))
        // .route("/account/:name/did", put(account::update_did))
        .with_state(app_state.clone())
        .fallback(notfound_404);

    router = router.nest("/api", api_router);

    // Logging layer
    router = router.layer(axum::middleware::from_fn(log_request_response::<Logger>));

    // Healthcheck layer
    let mut healthcheck_router = Router::new()
        .route("/healthcheck", get(health::healthcheck))
        .with_state(app_state);

    healthcheck_router = healthcheck_router.layer(axum::middleware::from_fn(
        log_request_response::<DebugOnlyLogger>,
    ));

    Router::merge(router, healthcheck_router)
}
