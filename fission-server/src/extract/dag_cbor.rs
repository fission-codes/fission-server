//! Axum extractor that serializes and deserializes DagCbor data using serde

use anyhow::Result;
use axum::{
    body::{Bytes, HttpBody},
    extract::{rejection::BytesRejection, FromRequest},
    http::{
        header::{ToStrError, CONTENT_TYPE},
        HeaderValue, Request, StatusCode,
    },
    response::{IntoResponse, Response},
    BoxError,
};
use serde::{de::DeserializeOwned, Serialize};
use serde_ipld_dagcbor::DecodeError;
use std::{convert::Infallible, fmt::Debug};

/// Newtype wrapper around dag-cbor (de-)serializable data
#[derive(Debug, Clone)]
pub struct DagCbor<M>(pub M);

/// Errors that can occur during dag-cbor deserialization
#[derive(Debug, thiserror::Error)]
pub enum DagCborRejection {
    /// When the Content-Type header is missing
    #[error("Missing Content-Type header on request, expected application/vnd.ipld.dag-cbor, but got nothing")]
    MissingContentType,

    /// When a Content-Type header was set, but unexpected.
    #[error("Incorrect mime type, expected application/vnd.ipld.dag-cbor, but got {0}")]
    UnexpectedContentType(mime::Mime),

    /// When the Content-Type header was set, but couldn't be parsed as a mime type
    #[error(
        "Failed parsing Content-Type header as mime type, expected application/vnd.ipld.dag-cbor"
    )]
    FailedToParseMime,

    /// When the request body couldn't be loaded before deserialization
    #[error("Unable to buffer the request body, perhaps it exceeded the 2MB limit")]
    FailedParsingRequestBytes,

    /// When dag-cbor deserialization into the target type fails
    #[error("Failed decoding dag-cbor: {0}")]
    FailedDecoding(#[from] DecodeError<Infallible>),
}

impl IntoResponse for DagCborRejection {
    fn into_response(self) -> Response {
        (
            match &self {
                Self::MissingContentType => StatusCode::BAD_REQUEST,
                Self::UnexpectedContentType(_) => StatusCode::BAD_REQUEST,
                Self::FailedToParseMime => StatusCode::BAD_REQUEST,
                Self::FailedParsingRequestBytes => StatusCode::PAYLOAD_TOO_LARGE,
                Self::FailedDecoding(_) => StatusCode::BAD_REQUEST,
            },
            self.to_string(),
        )
            .into_response()
    }
}

impl From<ToStrError> for DagCborRejection {
    fn from(_err: ToStrError) -> Self {
        Self::FailedToParseMime
    }
}

impl From<mime::FromStrError> for DagCborRejection {
    fn from(_err: mime::FromStrError) -> Self {
        Self::FailedToParseMime
    }
}

impl From<BytesRejection> for DagCborRejection {
    fn from(_err: BytesRejection) -> Self {
        Self::FailedParsingRequestBytes
    }
}

#[async_trait::async_trait]
impl<S, M, B> FromRequest<S, B> for DagCbor<M>
where
    M: DeserializeOwned + Debug,
    B: HttpBody + Send + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
    S: Send + Sync,
{
    type Rejection = DagCborRejection;

    async fn from_request(req: Request<B>, state: &S) -> Result<Self, Self::Rejection> {
        let mime = req
            .headers()
            .get(CONTENT_TYPE)
            .ok_or(DagCborRejection::MissingContentType)?
            .to_str()?
            .parse::<mime::Mime>()?;

        if mime.essence_str() != "application/vnd.ipld.dag-cbor" {
            return Err(DagCborRejection::UnexpectedContentType(mime));
        }

        let bytes = Bytes::from_request(req, state).await?;
        Ok(DagCbor(serde_ipld_dagcbor::from_slice(bytes.as_ref())?))
    }
}

impl<M> IntoResponse for DagCbor<M>
where
    M: Serialize,
{
    fn into_response(self) -> Response {
        match serde_ipld_dagcbor::to_vec(&self.0) {
            Ok(bytes) => (
                [(
                    CONTENT_TYPE,
                    HeaderValue::from_static("application/vnd.ipld.dag-cbor"),
                )],
                bytes,
            )
                .into_response(),
            Err(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                [(
                    CONTENT_TYPE,
                    HeaderValue::from_static(mime::TEXT_PLAIN_UTF_8.as_ref()),
                )],
                format!("Failed to encode dag-cbor: {err}"),
            )
                .into_response(),
        }
    }
}
