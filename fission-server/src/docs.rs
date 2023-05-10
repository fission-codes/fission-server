//! OpenAPI doc generation.

use crate::{
    error::AppError,
    models::email_verification,
    routes::{account, auth, health, ping, volume},
};
use utoipa::OpenApi;

/// API documentation generator.
#[derive(OpenApi)]
#[openapi(
        paths(health::healthcheck, ping::get, auth::request_token,
        account::create_account, account::get_account, account::update_did,
        volume::get_cid, volume::update_cid),
        components(schemas(AppError, email_verification::Request, auth::Response, account::Account, volume::Volume)),
        tags(
            (name = "", description = "fission-server service/middleware")
        )
    )]

/// Tied to OpenAPI documentation.
#[derive(Debug)]
pub struct ApiDoc;
