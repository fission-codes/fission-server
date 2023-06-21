//! OpenAPI doc generation.

use crate::{
    error::AppError,
    extract::authority_addon::UcanAddon,
    models::{account::NewAccount, email_verification, volume::NewVolumeRecord},
    routes::{account, auth, health, ping, volume},
};
use utoipa::OpenApi;

/// API documentation generator.
#[derive(OpenApi)]
#[openapi(
        paths(health::healthcheck, ping::get, auth::request_token,
account::create_account, account::get_account, account::update_did,
volume::get_cid, volume::update_cid),
        components(schemas(AppError, email_verification::Request, auth::Response, NewAccount, NewVolumeRecord, health::HealthcheckResponse)),
        modifiers(&UcanAddon),
        tags(
            (name = "", description = "fission-server service/middleware")
        )
    )]

/// Tied to OpenAPI documentation.
#[derive(Debug)]
pub struct ApiDoc;
