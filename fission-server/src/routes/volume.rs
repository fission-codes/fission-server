//! Volume routes

use crate::{
    app_state::AppState,
    authority::Authority,
    db::{self},
    error::{AppError, AppResult},
    models::{account::Account, volume::NewVolumeRecord},
    traits::ServerSetup,
};
use axum::extract::{Json, Path, State};
use http::StatusCode;

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
pub async fn get_cid<S: ServerSetup>(
    State(state): State<AppState<S>>,
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

#[utoipa::path(
    post,
    path = "/api/account/{username}/volume",
    security(
        ("ucan_bearer" = []),
    ),
    responses(
        (status = 200, description = "Successfully created Volume", body=NewVolume),
        (status = 400, description = "Invalid request", body=AppError),
        (status = 401, description = "Unauthorized"),
    )
)]

/// Handler to create a new volume for an account
pub async fn create_volume<S: ServerSetup>(
    State(state): State<AppState<S>>,
    authority: Authority,
    Path(username): Path<String>,
    Json(payload): Json<NewVolumeRecord>,
) -> AppResult<(StatusCode, Json<NewVolumeRecord>)> {
    let mut conn = db::connect(&state.db_pool).await?;
    let account = Account::find_by_username(&mut conn, username).await?;

    let allowed = authority
        .has_capability("ucan:*", "ucan/*", &account.did)
        .await?;
    if allowed {
        let volume = account
            .set_volume_cid(&mut conn, &payload.cid, &state.ipfs_db)
            .await?;
        Ok((StatusCode::CREATED, Json(volume)))
    } else {
        Err(AppError::new(
            StatusCode::UNAUTHORIZED,
            Some("No valid UCAN found"),
        ))
    }
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
pub async fn update_cid<S: ServerSetup>(
    State(state): State<AppState<S>>,
    authority: Authority,
    Path(username): Path<String>,
    Json(payload): Json<NewVolumeRecord>,
) -> AppResult<(StatusCode, Json<NewVolumeRecord>)> {
    let mut conn = db::connect(&state.db_pool).await?;
    let account = Account::find_by_username(&mut conn, username).await?;

    let allowed = authority
        .has_capability("ucan:*", "ucan/*", &account.did)
        .await;

    // FIXME: this is a hack to get around the fact that rs-ucan
    // doesn't produce very helpful errors
    if allowed.is_err() {
        return Err(AppError::new(
            StatusCode::UNAUTHORIZED,
            Some("No valid UCAN found"),
        ));
    }

    if let Ok(allowed) = allowed {
        if allowed {
            let volume: NewVolumeRecord = if account.volume_id.is_some() {
                account
                    .update_volume_cid(&mut conn, &payload.cid, &state.ipfs_db)
                    .await?
            } else {
                account
                    .set_volume_cid(&mut conn, &payload.cid, &state.ipfs_db)
                    .await?
            };

            Ok((StatusCode::OK, Json(volume)))
        } else {
            Err(AppError::new(
                StatusCode::UNAUTHORIZED,
                Some("No valid UCAN found"),
            ))
        }
    } else {
        Err(AppError::new(
            StatusCode::UNAUTHORIZED,
            Some("Error interpreting UCAN. Unable to proceed. Maybe supply some proofs?"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use http::{Method, StatusCode};
    use serde_json::json;
    use stringreader::StringReader;
    use tracing_test::traced_test;
    use ucan::crypto::KeyMaterial;

    use crate::{
        models::account::RootAccount,
        test_utils::{test_context::TestContext, RouteBuilder, UcanBuilder},
    };

    #[tokio::test]
    #[traced_test]
    async fn test_create_volume_ok() -> Result<()> {
        let ctx = TestContext::new().await;

        let mut conn = ctx.get_db_conn().await;

        // Agent UCAN/DID
        let (_, agent_keypair) = UcanBuilder::default().finalize().await?;

        let username = "tuttle";
        let email = "tuttle@heating.engineer";
        let agent_did = agent_keypair.get_did().await?;

        let root_account = RootAccount::new(
            &mut conn,
            username.to_string(),
            email.to_string(),
            &agent_did,
        )
        .await?;

        let (ucan, _) = UcanBuilder::default()
            .with_issuer(agent_keypair)
            .with_proof(root_account.ucan.clone())
            .with_capability("ucan:*", "ucan/*")
            .finalize()
            .await?;

        let hw_string = StringReader::new("Hello World!");
        let hw_cid = ctx.ipfs_db().add(hw_string)?;

        let (status, _) = RouteBuilder::new(ctx.app(), Method::POST, "/api/account/tuttle/volume")
            .with_ucan(ucan)
            .with_ucan_proof(root_account.ucan)
            .with_json_body(json!({ "cid": hw_cid.to_string() }))?
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
            .await?;

        assert_eq!(status, StatusCode::UNAUTHORIZED);

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn test_update_volume_ok() -> Result<()> {
        let ctx = TestContext::new().await;

        let mut conn = ctx.get_db_conn().await;

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

        let hw_string = StringReader::new("Hello World!");
        let hw_cid = ctx.ipfs_db().add(hw_string)?;

        root_account
            .account
            .set_volume_cid(&mut conn, &hw_cid.to_string(), &ctx.ipfs_db())
            .await?;

        let (ucan, _) = UcanBuilder::default()
            .with_issuer(issuer)
            .with_proof(root_account.ucan.clone())
            .with_capability("ucan:*", "ucan/*")
            .finalize()
            .await?;

        let (status, _) =
            RouteBuilder::new(ctx.app(), Method::PUT, "/api/account/tuttle/volume/cid")
                .with_ucan(ucan)
                .with_ucan_proof(root_account.ucan)
                .with_json_body(json!({ "cid": "Qmf1rtki74jvYmGeqaaV51hzeiaa6DyWc98fzDiuPatzyy" }))?
                .into_raw_response()
                .await?;

        assert_eq!(status, StatusCode::OK);

        Ok(())
    }

    #[tokio::test]
    async fn test_update_volume_pin_failure() -> Result<()> {
        let ctx = TestContext::new().await;

        let mut conn = ctx.get_db_conn().await;

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
            .with_proof(root_account.ucan)
            .finalize()
            .await?;

        let (status, _) = RouteBuilder::new(ctx.app(), Method::POST, "/api/account/tuttle/volume")
            .with_ucan(ucan)
            .with_json_body(
                json!({ "cid": "bafybeicn7i3soqdgr7dwnrwytgq4zxy7a5jpkizrvhm5mv6bgjd32wm3q4" }),
            )?
            .into_raw_response()
            .await?;

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);

        Ok(())
    }

    #[tokio::test]
    async fn test_update_volume_not_found() -> Result<()> {
        let ctx = TestContext::new().await;

        let (_, issuer) = UcanBuilder::default().finalize().await?;

        let (ucan, _) = UcanBuilder::default()
            .with_issuer(issuer)
            .finalize()
            .await?;

        let (status, _) =
            RouteBuilder::new(ctx.app(), Method::PUT, "/api/account/buttle/volume/cid")
                .with_ucan(ucan)
                .with_json_body(json!({ "cid": "Qmf1rtki74jvYmGeqaaV51hzeiaa6DyWc98fzDiuPatzyy" }))?
                .into_raw_response()
                .await?;

        assert_eq!(status, StatusCode::NOT_FOUND);

        Ok(())
    }

    #[tokio::test]
    async fn test_get_volume_ok() -> Result<()> {
        // this method might be deprecated in favour of the DoH method?

        let ctx = TestContext::new().await;
        let mut conn = ctx.get_db_conn().await;

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

        root_account
            .account
            .set_volume_cid(
                &mut conn,
                "Qmf1rtki74jvYmGeqaaV51hzeiaa6DyWc98fzDiuPatzyy",
                &ctx.ipfs_db(),
            )
            .await?;

        let (status, _) =
            RouteBuilder::new(ctx.app(), Method::GET, "/api/account/tuttle/volume/cid")
                .into_raw_response()
                .await?;

        assert_eq!(status, StatusCode::OK);

        Ok(())
    }

    #[tokio::test]
    async fn test_get_volume_not_found() -> Result<()> {
        let ctx = TestContext::new().await;
        let mut conn = ctx.get_db_conn().await;

        let (_, issuer) = UcanBuilder::default().finalize().await?;

        let username = "tuttle";
        let email = "tuttle@heating.engineer";
        let agent_did = issuer.get_did().await?;

        RootAccount::new(
            &mut conn,
            username.to_string(),
            email.to_string(),
            &agent_did,
        )
        .await?;

        let ctx = TestContext::new().await;

        let (status, _) =
            RouteBuilder::new(ctx.app(), Method::GET, "/api/account/buttle/volume/cid")
                .into_raw_response()
                .await?;

        assert_eq!(status, StatusCode::NOT_FOUND);

        Ok(())
    }
}
