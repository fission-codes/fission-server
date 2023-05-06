//! OpenAPI doc generation.

use crate::{
    error::AppError,
    routes::{auth, health, ping},
};
use utoipa::OpenApi;

/// API documentation generator.
#[derive(OpenApi)]
#[openapi(
        paths(health::healthcheck, ping::get, auth::request_token),
        components(schemas(AppError, auth::Email, auth::Response)),
        tags(
            (name = "", description = "fission-server service/middleware")
        )
    )]

/// Tied to OpenAPI documentation.
#[derive(Debug)]
pub struct ApiDoc;
