//! Main [axum::Router] interface for webserver.

use crate::{
    db::connection::Pool,
    middleware::logging::{log_request_response, DebugOnlyLogger, Logger},
    routes::{account, auth, fallback::notfound_404, health, ping, volume},
};
use axum::{
    routing::{get, post, put},
    Router,
};
use tower_http::cors::{Any, CorsLayer};

/// Setup main router for application.
pub fn setup_app_router(db_pool: Pool) -> Router {
    let mut router = Router::new()
        .route("/ping", get(ping::get))
        .fallback(notfound_404)
        .with_state(db_pool.clone());

    // I fucking hate CORS.
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

    let api_router = Router::new()
        .route("/auth/email/verify", post(auth::request_token))
        .route("/account", post(account::create_account))
        .route("/account/:name", get(account::get_account))
        .route("/account/:name/did", put(account::update_did))
        .route("/account/:name/volume/cid", get(volume::get_cid))
        .route("/account/:name/volume/cid", put(volume::update_cid))
        .layer(cors)
        .with_state(db_pool)
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
