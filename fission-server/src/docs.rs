//! OpenAPI doc generation.

use crate::{
    error::AppError,
    extract::authority_addon::UcanAddon,
    models::{account::RootAccount, email_verification, volume::NewVolumeRecord},
    routes::{account, auth, health, ping},
};
use utoipa::OpenApi;

/// API documentation generator.
#[derive(OpenApi)]
#[openapi(
    paths(
        health::healthcheck,
        ping::get,
        auth::request_token,
        account::create_account,
        account::get_account,
    ),
    components(
        schemas(
            AppError,
            email_verification::Request,
            auth::VerificationCodeResponse,
            account::AccountCreationRequest,
            account::AccountResponse,
            RootAccount,
            NewVolumeRecord,
            health::HealthcheckResponse
        )
    ),
    modifiers(&UcanAddon),
    tags(
        (name = "", description = "fission-server service/middleware")
    )
)]

/// Tied to OpenAPI documentation.
#[derive(Debug)]
pub struct ApiDoc;
