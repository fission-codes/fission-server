//! Main [axum::Router] interface for webserver.

use crate::{
    app_state::AppState,
    middleware::logging::{log_request_response, DebugOnlyLogger, Logger},
    routes::{
        account, auth, capability_indexing, doh, fallback::notfound_404, health, ipfs, ping,
        revocations, volume, ws,
    },
    setups::ServerSetup,
};
use axum::{
    routing::{delete, get, patch, post, put},
    Router,
};
use tower_http::cors::{Any, CorsLayer};

/// Setup main router for application.
pub fn setup_app_router<S: ServerSetup>(app_state: AppState<S>) -> Router {
    let cors = CorsLayer::new()
        .allow_methods(Any)
        .allow_headers(Any)
        .allow_origin(Any);

    let mut router = Router::new()
        .route("/dns-query", get(doh::get).post(doh::post))
        .route("/ipfs/peers", get(ipfs::peers))
        .route("/ping", get(ping::get))
        .fallback(notfound_404)
        .with_state(app_state.clone());

    let api_router = Router::new()
        .route("/relay/:topic", get(ws::handler))
        .route("/auth/email/verify", post(auth::request_token))
        .route("/account", post(account::create_account))
        .route("/account", delete(account::delete_account))
        .route("/account", get(account::get_account))
        .route("/account/member-number", get(account::get_member_number))
        .route("/account/:did/link", post(account::link_account))
        .route(
            "/account/username/:username",
            patch(account::patch_username),
        )
        .route("/account/handle/:handle", patch(account::patch_handle))
        .route("/account/handle", delete(account::delete_handle))
        .route("/volume/push/:cid", put(volume::push_volume_cid))
        .route("/volume/pull/:cid", get(volume::pull_volume_cid))
        .route("/volume/pull/:cid", post(volume::pull_volume_cid))
        .route("/capabilities", get(capability_indexing::get_capabilities))
        .route("/revocations", post(revocations::post_revocation))
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
