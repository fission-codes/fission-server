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
use utoipa::ToSchema;

use std::sync::{Arc, RwLock};

#[derive(Clone, Debug, ToSchema)]
/// The App State
pub struct AppState {
    /// An in-memory map of request tokens (email -> token)
    pub request_tokens: Arc<RwLock<std::collections::HashMap<String, u32>>>,
    /// An in-memory map of accounts (username -> account)
    pub accounts: Arc<RwLock<std::collections::HashMap<String, account::Account>>>,
    //    pub volumes: Arc<RwLock<std::collections::HashMap<String, volume::Volume>>>
}

/// Setup main router for application.
pub fn setup_app_router(db_pool: Pool) -> Router {
    let state = AppState {
        request_tokens: Arc::new(RwLock::new(std::collections::HashMap::new())),
        accounts: Arc::new(RwLock::new(std::collections::HashMap::new())),
    };

    let mut router = Router::new()
        .route("/ping", get(ping::get))
        .fallback(notfound_404)
        .with_state(db_pool);

    let api_router = Router::new()
        .route("/auth/requestToken", post(auth::request_token))
        .route("/account", post(account::create_account))
        //        .route("/account/{name}", get(account::get_account))
        .with_state(state)
        .fallback(notfound_404);

    router = router.nest("/api", api_router);

    // Logging layer
    router = router.layer(axum::middleware::from_fn(log_request_response::<Logger>));

    // Healthcheck layer
    let mut healthcheck_router = Router::new().route("/healthcheck", get(health::healthcheck));

    healthcheck_router = healthcheck_router.layer(axum::middleware::from_fn(
        log_request_response::<DebugOnlyLogger>,
    ));

    Router::merge(router, healthcheck_router)
}
