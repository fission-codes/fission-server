//! Volume routes

use crate::{
    app_state::AppState,
    authority::Authority,
    db::{self},
    error::{AppError, AppResult},
    models::{account::Account, volume::NewVolumeRecord},
};
use axum::extract::{Json, Path, State};
use fission_core::authority::key_material::SUPPORTED_KEYS;
use http::{HeaderMap, StatusCode};
use tracing::log;
use ucan::{
    chain::ProofChain,
    store::{MemoryStore, UcanJwtStore, }, capability::Capability,
};

#[utoipa::path(
    get,
    path = "/api/account/{username}/volume/cid",
    security(
        ("ucan_bearer" = []),
    ),
    responses(
        (status = 200, description = "Found volume", body=account::AccountRequest),
        (status = 400, description = "Invalid request", body=AppError),
        (status = 401, description = "Unauthorized"),
    )
)]

/// GET handler to retrieve account volume CID
pub async fn get_cid(
    State(state): State<AppState>,
    Path(username): Path<String>,
) -> AppResult<(StatusCode, Json<NewVolumeRecord>)> {
    let mut conn = db::connect(&state.db_pool).await?;

    let volume = Account::find_by_username(&mut conn, username)
        .await?
        .get_volume(&mut conn)
        .await?;

    if let Some(volume) = volume {
        Ok((StatusCode::OK, Json(volume)))
    } else {
        Ok((StatusCode::NO_CONTENT, Json(NewVolumeRecord::default())))
    }
}

/// Handler to create a new volume for an account
pub async fn create_volume(
    State(state): State<AppState>,
    authority: Authority,
    Path(username): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<NewVolumeRecord>,
) -> AppResult<(StatusCode, Json<NewVolumeRecord>)> {
    tracing::info!("Creating volume for {}", username);

    let mut conn = db::connect(&state.db_pool).await?;
    let account = Account::find_by_username(&mut conn, username).await?;

    let mut store = MemoryStore::default();
    let mut did_parser = ucan::crypto::did::DidParser::new(SUPPORTED_KEYS);

    for proof in headers.get_all("ucan") {
        let Some((_, ucan)) = proof.to_str()?.split_once(" ") else {
            return Err(AppError::new(StatusCode::BAD_REQUEST, Some("Invalid UCAN")));
        };
        store.write_token(ucan).await?; //&ucan.encode().unwrap());
    }

    let now_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|t| t.as_secs());

    let chain = ProofChain::from_ucan(authority.ucan, now_time, &mut did_parser, &store).await?;

    chain
        .ucan()
        .validate(now_time, &mut did_parser)
        .await
        .map_err(|error| {
            log::error!("Error validating UCAN: {}", error);
            AppError::new(StatusCode::UNAUTHORIZED, Some("Invalid UCAN"))
        })?;

    let capability_infos = chain.reduce_capabilities(&fission_core::capabilities::delegation::SEMANTICS);

    tracing::info!("Capability infos: {:?}", capability_infos);

    for info in capability_infos {
        tracing::info!("Capability: {:?} {}", info, &account.did);
        if info.originators.contains(&account.did)
            // && info.capability.enables("ucan/*".into())
        {
            let volume = account.set_volume_cid(&mut conn, payload.cid).await?;
            return Ok((StatusCode::CREATED, Json(volume)))
        }
    }

    return Err(AppError::new(StatusCode::UNAUTHORIZED, Some("No valid UCAN found")));

}

#[utoipa::path(
    put,
    path = "/api/account/{username}/volume/cid",
    security(
        ("ucan_bearer" = []),
    ),
    responses(
        (status = 200, description = "Successfully updated Volume", body=NewVolume),
        (status = 400, description = "Invalid request", body=AppError),
        (status = 401, description = "Unauthorized"),
    )
)]

/// Handler to update the CID associated with an account's volume
pub async fn update_cid(
    State(state): State<AppState>,
    _authority: Authority,
    Path(username): Path<String>,
    Json(payload): Json<NewVolumeRecord>,
) -> AppResult<(StatusCode, Json<NewVolumeRecord>)> {
    let mut conn = db::connect(&state.db_pool).await?;
    let account = Account::find_by_username(&mut conn, username).await?;
    let volume = account.update_volume_cid(&mut conn, &payload.cid).await?;

    Ok((StatusCode::OK, Json(volume)))
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use diesel::ExpressionMethods;
    use diesel_async::RunQueryDsl;
    use http::{Method, StatusCode};
    use serde_json::json;
    use tokio::sync::broadcast;
    use tracing::log;
    use tracing_test::traced_test;
    use ucan::crypto::KeyMaterial;

    use crate::{
        db::schema::{accounts, volumes},
        error::{AppError, ErrorResponse},
        models::{
            account::{AccountRequest, RootAccount},
            volume::NewVolumeRecord,
        },
        routes::auth::VerificationCodeResponse,
        test_utils::{test_context::TestContext, RouteBuilder, UcanBuilder},
    };

    #[tokio::test]
    #[traced_test]
    async fn test_create_volume_ok() -> Result<()> {
        let ctx = TestContext::new().await;

        let mut conn = ctx.get_db_conn().await;

        // Agent UCAN/DID
        let (_, issuer) = UcanBuilder::default().finalize().await?;

        let username = "tuttle";
        let email = "tuttle@heating.engineer";
        let agent_did = issuer.get_did().await?;

        let root_account = RootAccount::new(
            &mut conn,
            username.to_string(),
            email.to_string(),
            &agent_did,
        )
        .await?;

        let (ucan, _) = UcanBuilder::default()
            .with_issuer(issuer)
            .with_proof(root_account.ucan.clone())
            .finalize()
            .await?;

        let (status, _) = RouteBuilder::new(ctx.app(), Method::POST, "/api/account/tuttle/volume")
            .with_ucan(ucan)
            .with_ucan_proof(root_account.ucan)
            .with_json_body(
                json!({ "cid": "bafybeicn7i3soqdgr7dwnrwytgq4zxy7a5jpkizrvhm5mv6bgjd32wm3q4" }),
            )?
            // .into_json_response::<NewVolumeRecord>()
            .into_raw_response()
            .await?;

        assert_eq!(status, StatusCode::CREATED);

        Ok(())
    }

    #[tokio::test]
    async fn test_create_volume_err_no_capability() -> Result<()> {
        let ctx = TestContext::new().await;

        let mut conn = ctx.get_db_conn().await;

        // Agent UCAN/DID
        let (_, issuer) = UcanBuilder::default().finalize().await?;

        let username = "buttle";
        let email = "buttle@central.services";
        let agent_did = issuer.get_did().await?;

        let _root_account = RootAccount::new(
            &mut conn,
            username.to_string(),
            email.to_string(),
            &agent_did,
        )
        .await?;

        let (ucan, _) = UcanBuilder::default()
            .with_issuer(issuer)
            // .with_proof(root_account.ucan)
            .finalize()
            .await?;

        let (status, _) = RouteBuilder::new(ctx.app(), Method::POST, "/api/account/buttle/volume")
            .with_ucan(ucan)
            .with_json_body(
                json!({ "cid": "bafybeicn7i3soqdgr7dwnrwytgq4zxy7a5jpkizrvhm5mv6bgjd32wm3q4" }),
            )?
        .into_raw_response()
            // .into_json_response::<NewVolumeRecord>()
            .await?;

        assert_eq!(status, StatusCode::UNAUTHORIZED);

        Ok(())
    }

    #[tokio::test]
    async fn test_update_volume_ok() -> Result<()> {
        Err(anyhow::anyhow!("Not implemented"))
    }

    #[tokio::test]
    async fn test_update_volume_not_found() -> Result<()> {
        Err(anyhow::anyhow!("Not implemented"))
    }

    #[tokio::test]
    async fn test_get_volume_ok() -> Result<()> {
        Err(anyhow::anyhow!("Not implemented"))
    }

    #[tokio::test]
    async fn test_get_volume_not_found() -> Result<()> {
        Err(anyhow::anyhow!("Not implemented"))
    }
}
