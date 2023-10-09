//! Main [axum::Router] interface for webserver.

use crate::{
    app_state::AppState,
    middleware::logging::{log_request_response, DebugOnlyLogger, Logger},
    routes::{account, auth, doh, fallback::notfound_404, health, ipfs, ping, ws},
    traits::ServerSetup,
};

use axum::{
    routing::{get, post, put},
    Router,
};
use tower_http::cors::{Any, CorsLayer};

/// Setup main router for application.
pub fn setup_app_router<S: ServerSetup + 'static>(app_state: AppState<S>) -> Router {
    let cors = CorsLayer::new()
        // allow `GET`, `POST`, and `PUT` when accessing the resource
        .allow_methods([http::Method::GET, http::Method::POST, http::Method::PUT])
        .allow_headers([
            http::header::AUTHORIZATION,
            http::header::CONTENT_TYPE,
            http::header::ACCEPT,
        ])
        // allow requests from any origin
        .allow_origin(Any);

    let mut router = Router::new()
        .route("/dns-query", get(doh::get).post(doh::post))
        .route("/ipfs/peers", get(ipfs::peers))
        .route("/ping", get(ping::get))
        .fallback(notfound_404)
        .with_state(app_state.clone());

    let api_router = Router::new()
        .route("/relay/:did", get(ws::handler))
        .route("/auth/email/verify", post(auth::request_token))
        .route("/account", post(account::create_account))
        .route("/account/:name", get(account::get_account))
        .route("/account/:name/did", put(account::update_did))
        .with_state(app_state.clone())
        .fallback(notfound_404);

    router = router.nest("/api/v0", api_router);

    // Additional layers
    router = router.layer(cors);
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
