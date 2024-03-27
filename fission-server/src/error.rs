//! Generic result/error resprentation(s).

use std::{convert::Infallible, fmt::Debug};

use axum::{
    extract::rejection::{ExtensionRejection, QueryRejection},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};

use http::header::ToStrError;
use libipld::codec::Codec;
use serde::{Deserialize, Serialize};
use ucan::{
    crypto::varsig,
    did::Did,
    invocation::{agent::ReceiveError, store::Store},
};
use ulid::Ulid;
use utoipa::ToSchema;
use validator::ValidationErrors;

/// Standard return type out of routes / handlers
pub type AppResult<T> = std::result::Result<T, AppError>;

/// Encodes [JSONAPI error object responses](https://jsonapi.org/examples/#error-objects).
///
/// JSONAPI error object -  ALL Fields are technically optional.
///
/// This struct uses the following guidelines:
///
/// 1. Always encode the StatusCode of the response
/// 2. Set the title to the `canonical_reason` of the status code.
///    According to spec, this should NOT change over time.
/// 3. For unrecoverable errors, encode the detail as the to_string of the error
///
/// Other fields not currently captured (but can be added)
///
/// - id - a unique identifier for the problem
/// - links - a link object with further information about the problem
/// - source - a JSON pointer indicating a problem in the request json OR
///   a parameter specifying a problematic query parameter
/// - meta - a meta object containing arbitrary information about the error
#[derive(ToSchema, thiserror::Error, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct AppError {
    #[schema(value_type = u16, example = 404)]
    #[serde(with = "crate::error::serde_status_code")]
    pub(crate) status: StatusCode,
    #[schema(example = "Not Found")]
    pub(crate) detail: Option<String>,
    #[schema(example = "Entity with id 123 not found")]
    pub(crate) title: Option<String>,
}

impl AppError {
    /// New instance of [AppError].
    pub fn new<M: ToString>(status_code: StatusCode, message: Option<M>) -> AppError {
        Self {
            status: status_code,
            title: Self::canonical_reason_to_string(&status_code),
            detail: message.map(|m| m.to_string()),
        }
    }

    /// [AppError] for [StatusCode::NOT_FOUND].
    pub fn not_found(id: Ulid) -> AppError {
        Self::new(
            StatusCode::NOT_FOUND,
            Some(format!("Entity with id {id} not found")),
        )
    }

    fn canonical_reason_to_string(status_code: &StatusCode) -> Option<String> {
        status_code.canonical_reason().map(|r| r.to_string())
    }
}

#[derive(Debug, Deserialize, Serialize)]
/// Error in JSON API response format.
pub struct ErrorResponse {
    pub(crate) errors: Vec<AppError>,
}

impl From<AppError> for ErrorResponse {
    fn from(e: AppError) -> Self {
        Self { errors: vec![e] }
    }
}

impl From<AppError> for (StatusCode, Json<ErrorResponse>) {
    fn from(app_error: AppError) -> Self {
        (app_error.status, Json(app_error.into()))
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let error_response: (StatusCode, Json<ErrorResponse>) = self.into();
        error_response.into_response()
    }
}

impl From<anyhow::Error> for AppError {
    fn from(err: anyhow::Error) -> Self {
        let err = match err.downcast::<diesel::result::Error>() {
            Ok(err) => return Self::from(err),
            Err(e) => e,
        };

        let err = match err.downcast::<rs_ucan::error::Error>() {
            Ok(err) => return Self::from(err),
            Err(e) => e,
        };

        let err = match err.downcast::<ValidationErrors>() {
            Ok(err) => return Self::from(err),
            Err(e) => e,
        };

        let err = match err.downcast::<QueryRejection>() {
            Ok(err) => return Self::from(err),
            Err(e) => e,
        };

        let err = match err.downcast::<ExtensionRejection>() {
            Ok(err) => return Self::from(err),
            Err(e) => e,
        };

        let err = match err.downcast::<car_mirror::Error>() {
            Ok(err) => return Self::from(err),
            Err(e) => e,
        };

        let err = match err.downcast::<cid::Error>() {
            Ok(err) => return Self::from(err),
            Err(e) => e,
        };

        Self::new(StatusCode::INTERNAL_SERVER_ERROR, Some(err))
    }
}

impl From<diesel::result::Error> for AppError {
    fn from(err: diesel::result::Error) -> Self {
        match err {
            diesel::result::Error::NotFound => {
                Self::new(StatusCode::NOT_FOUND, Some("Resource Not Found"))
            }
            diesel::result::Error::DatabaseError(
                diesel::result::DatabaseErrorKind::UniqueViolation,
                info,
            ) => Self::new(
                StatusCode::CONFLICT,
                Some(match info.details() {
                    Some(details) => format!("{} ({details})", info.message()),
                    None => info.message().to_string(),
                }),
            ),
            _ => Self::new(StatusCode::INTERNAL_SERVER_ERROR, Some(err)),
        }
    }
}

impl From<ToStrError> for AppError {
    fn from(err: ToStrError) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, Some(err))
    }
}

impl From<String> for AppError {
    fn from(err: String) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, Some(err))
    }
}

impl From<rs_ucan::error::Error> for AppError {
    fn from(err: rs_ucan::error::Error) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, Some(err))
    }
}

impl From<ValidationErrors> for AppError {
    fn from(err: ValidationErrors) -> Self {
        Self::new(StatusCode::BAD_REQUEST, Some(err))
    }
}

impl From<QueryRejection> for AppError {
    fn from(value: QueryRejection) -> Self {
        Self::new(StatusCode::BAD_REQUEST, Some(value))
    }
}

impl From<ExtensionRejection> for AppError {
    fn from(value: ExtensionRejection) -> Self {
        Self::new(StatusCode::BAD_REQUEST, Some(value))
    }
}

impl From<Infallible> for AppError {
    fn from(the_impossible: Infallible) -> Self {
        match the_impossible {}
    }
}

impl<E: Into<AppError>> From<ucan::delegation::store::DelegationStoreError<E>> for AppError {
    fn from(err: ucan::delegation::store::DelegationStoreError<E>) -> Self {
        match err {
            ucan::delegation::store::DelegationStoreError::CannotMakeCid(e) => {
                AppError::new(StatusCode::INTERNAL_SERVER_ERROR, Some(e))
            }
            ucan::delegation::store::DelegationStoreError::StoreError(e) => e.into(),
        }
    }
}

impl<T, DID: Did + Debug, D, S: Store<T, DID, V, C>, V: varsig::Header<C>, C: Codec>
    From<ReceiveError<T, DID, D, S, V, C>> for AppError
{
    fn from(err: ReceiveError<T, DID, D, S, V, C>) -> Self {
        match err {
            ReceiveError::DelegationNotFound(_) => {
                AppError::new(StatusCode::FORBIDDEN, Some("Delegation not found"))
            }
            ReceiveError::EncodingError(_) => {
                AppError::new(StatusCode::BAD_REQUEST, Some("UCANs invalidly encoded"))
            }
            ReceiveError::SigVerifyError(_) => AppError::new(
                StatusCode::BAD_REQUEST,
                Some("UCAN signature couldn't be verified"),
            ),
            ReceiveError::InvocationStoreError(_) => AppError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                Some("Something went wrong in the invocation store"),
            ),
            ReceiveError::DelegationStoreError(_) => AppError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                Some("Something went wrong in the delegation store"),
            ),
            ReceiveError::ValidationError(e) => AppError::new(StatusCode::FORBIDDEN, Some(e)),
        }
    }
}

impl From<car_mirror::Error> for AppError {
    fn from(err: car_mirror::Error) -> Self {
        match err {
            car_mirror::Error::BlockStoreError(err) => AppError::from(err),
            _ => Self::new(StatusCode::INTERNAL_SERVER_ERROR, Some(err)),
        }
    }
}

impl From<&car_mirror::Error> for AppError {
    fn from(err: &car_mirror::Error) -> Self {
        match err {
            car_mirror::Error::BlockStoreError(err) => AppError::from(err),
            _ => Self::new(StatusCode::INTERNAL_SERVER_ERROR, Some(err)),
        }
    }
}

impl From<wnfs::common::BlockStoreError> for AppError {
    fn from(err: wnfs::common::BlockStoreError) -> Self {
        match err {
            wnfs::common::BlockStoreError::CIDNotFound(_) => {
                Self::new(StatusCode::NOT_FOUND, Some(err))
            }
            _ => Self::new(StatusCode::INTERNAL_SERVER_ERROR, Some(err)),
        }
    }
}

impl From<&wnfs::common::BlockStoreError> for AppError {
    fn from(err: &wnfs::common::BlockStoreError) -> Self {
        match err {
            wnfs::common::BlockStoreError::CIDNotFound(_) => {
                Self::new(StatusCode::NOT_FOUND, Some(err))
            }
            _ => Self::new(StatusCode::INTERNAL_SERVER_ERROR, Some(err)),
        }
    }
}

impl From<cid::Error> for AppError {
    fn from(err: cid::Error) -> Self {
        Self::new(StatusCode::BAD_REQUEST, Some(err))
    }
}

impl From<std::io::Error> for AppError {
    fn from(err: std::io::Error) -> Self {
        if let Some(err) = err.get_ref() {
            if let Some(err) = err.downcast_ref::<car_mirror::Error>() {
                return Self::from(err);
            }

            if let Some(err) = err.downcast_ref::<wnfs::common::BlockStoreError>() {
                return Self::from(err);
            }
        }

        Self::new(StatusCode::INTERNAL_SERVER_ERROR, Some(err))
    }
}

/// Serialize/Deserializer for status codes.
///
/// This is needed because status code according to JSON API spec must
/// be the status code as a STRING.
///
/// We could have used http_serde, but it encodes the status code as a NUMBER.
pub mod serde_status_code {
    use http::StatusCode;
    use serde::{de::Unexpected, Deserialize, Deserializer, Serialize, Serializer};

    /// Serialize [StatusCode]s.
    pub fn serialize<S: Serializer>(status: &StatusCode, ser: S) -> Result<S::Ok, S::Error> {
        String::serialize(&status.as_u16().to_string(), ser)
    }

    /// Deserialize [StatusCode]s.
    pub fn deserialize<'de, D>(de: D) -> Result<StatusCode, D::Error>
    where
        D: Deserializer<'de>,
    {
        let str = String::deserialize(de)?;
        StatusCode::from_bytes(str.as_bytes()).map_err(|_| {
            serde::de::Error::invalid_value(
                Unexpected::Str(str.as_str()),
                &"A valid http status code",
            )
        })
    }
}

// Needed to support thiserror::Error, outputs debug for AppError
impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[cfg(test)]
/// Parse the app error out of the json body
pub async fn parse_error(response: Response) -> AppError {
    let body_bytes = hyper::body::to_bytes(response.into_body()).await.unwrap();
    let mut err_response: ErrorResponse = serde_json::from_slice(&body_bytes).unwrap();
    err_response.errors.remove(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use testresult::TestResult;

    #[test]
    fn test_from_anyhow_error() {
        let err: AppError = anyhow::anyhow!("FAIL").into();
        assert_eq!(err.detail.unwrap(), "FAIL".to_string());
        assert_eq!(
            err.title,
            StatusCode::INTERNAL_SERVER_ERROR
                .canonical_reason()
                .map(|r| r.to_string())
        );

        assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn test_not_found() {
        let id = Ulid::new();
        let err = AppError::not_found(id);

        assert_eq!(err.status, StatusCode::NOT_FOUND);
        assert_eq!(
            err.title,
            StatusCode::NOT_FOUND
                .canonical_reason()
                .map(|r| r.to_string())
        );
        assert_eq!(
            err.detail.unwrap(),
            format!("Entity with id {id} not found")
        );
    }

    #[test_log::test(tokio::test)]
    async fn test_json_api_error_response() -> TestResult {
        // verify that our json api response complies with the standard
        let id = Ulid::new();
        let err = AppError::not_found(id);
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let err = parse_error(response).await;

        // Check that the result is all good
        assert_eq!(err.status, StatusCode::NOT_FOUND);
        assert_eq!(
            err.title,
            StatusCode::NOT_FOUND
                .canonical_reason()
                .map(|r| r.to_string())
        );
        assert_eq!(
            err.detail.unwrap(),
            format!("Entity with id {id} not found")
        );

        Ok(())
    }
}
