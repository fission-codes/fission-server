//! OpenAPI doc generation.

use crate::{
    error::AppError,
    extract::authority_addon::UcanAddon,
    models::account::{Account, AccountAndAuth},
    routes::{account, auth, capability_indexing, health, ping, revocations},
};
use fission_core::{
    common::{
        AccountCreationRequest, AccountLinkRequest, AccountResponse, DidResponse,
        EmailVerifyRequest, SuccessResponse, UcansResponse,
    },
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
        account::link_account,
        account::get_account,
        account::get_did,
        revocations::post_revocation,
        capability_indexing::get_capabilities,
    ),
    components(
        schemas(
            AppError,
            EmailVerifyRequest,
            SuccessResponse,
            AccountCreationRequest,
            AccountLinkRequest,
            AccountResponse,
            UcansResponse,
            AccountAndAuth,
            Account,
            DidResponse,
            Revocation,
            health::HealthcheckResponse
        )
    ),
    modifiers(&UcanAddon),
)]

/// Tied to OpenAPI documentation.
#[derive(Debug)]
pub struct ApiDoc;
