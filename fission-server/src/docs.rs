//! OpenAPI doc generation.

use crate::{
    error::AppError,
    extract::authority_addon::UcanAddon,
    models::account::{Account, RootAccount},
    routes::{account, auth, health, ping, revocations},
};
use fission_core::{
    common::{AccountCreationRequest, AccountResponse, EmailVerifyRequest, SuccessResponse},
    revocation::Revocation,
};
use utoipa::OpenApi;

/// API documentation generator.
#[derive(OpenApi)]
#[openapi(
    paths(
        health::healthcheck,
        ping::get,
        auth::request_token,
        auth::server_did,
        account::create_account,
        account::get_account,
        account::get_did,
        revocations::post_revocation,
    ),
    components(
        schemas(
            AppError,
            EmailVerifyRequest,
            SuccessResponse,
            AccountCreationRequest,
            AccountResponse,
            RootAccount,
            Account,
            Revocation,
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
