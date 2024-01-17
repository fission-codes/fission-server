//! OpenAPI doc generation.

use crate::{
    error::AppError,
    extract::authority_addon::UcanAddon,
    models::account::AccountAndAuth,
    routes::{account, auth, capability_indexing, health, ping, revocations},
};
use fission_core::{
    common::{
        Account, AccountCreationRequest, AccountLinkRequest, DidResponse, EmailVerifyRequest,
        SuccessResponse, UcansResponse,
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
        account::patch_username,
        account::patch_handle,
        account::delete_account,
        revocations::post_revocation,
        capability_indexing::get_capabilities,
    ),
    components(
        schemas(
            AppError,
            EmailVerifyRequest,
            SuccessResponse,
            Account,
            AccountCreationRequest,
            AccountLinkRequest,
            UcansResponse,
            AccountAndAuth,
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
