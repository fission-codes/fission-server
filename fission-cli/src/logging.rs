use anyhow::anyhow;
use http_cache_reqwest::{CacheManager, HttpResponse};
use http_cache_semantics::CachePolicy;
use reqwest::{Request, Response};
use reqwest_middleware::{Middleware, Next};
use serde::{Deserialize, Serialize};
use task_local_extensions::Extensions;

pub(crate) struct LogAndHandleErrorMiddleware;

#[async_trait::async_trait]
impl Middleware for LogAndHandleErrorMiddleware {
    async fn handle(
        &self,
        req: Request,
        extensions: &mut Extensions,
        next: Next<'_>,
    ) -> reqwest_middleware::Result<Response> {
        tracing::info!(
            url = %req.url(),
            method = %req.method(),
            headers = ?req.headers(),
            "Running request"
        );
        match next.run(req, extensions).await {
            Ok(resp) => {
                let status = resp.status();
                if status.is_client_error() {
                    let body = resp.text().await?;
                    tracing::error!(?status, %body, "Client error on response");
                    Err(anyhow!("Client error (status code {status}): {body}").into())
                } else if status.is_server_error() {
                    let body = resp.text().await?;
                    tracing::error!(?status, %body, "Server error on response");
                    Err(anyhow!("Server error (status code {status}): {body}").into())
                } else {
                    let content_length = resp.content_length();
                    tracing::info!(?status, ?content_length, "Got response");
                    Ok(resp)
                }
            }
            Err(e) => Err(e),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct ErrorResponse {
    errors: Vec<Error>,
}

#[derive(Serialize, Deserialize)]
struct Error {
    status: u16,
    detail: Option<String>,
    title: Option<String>,
}
pub(crate) struct LoggingCacheManager<T> {
    inner: T,
}

impl<T: CacheManager> LoggingCacheManager<T> {
    pub(crate) fn new(inner: T) -> Self {
        LoggingCacheManager { inner }
    }
}

#[async_trait::async_trait]
impl<T: CacheManager> CacheManager for LoggingCacheManager<T> {
    async fn get(
        &self,
        cache_key: &str,
    ) -> http_cache::Result<Option<(HttpResponse, CachePolicy)>> {
        tracing::info!(%cache_key, "Accessing HTTP cache");
        let value = self.inner.get(cache_key).await?;
        if value.is_some() {
            tracing::info!("HTTP cache hit");
        } else {
            tracing::info!("HTTP cache miss");
        }
        Ok(value)
    }

    async fn put(
        &self,
        cache_key: String,
        res: HttpResponse,
        policy: CachePolicy,
    ) -> http_cache::Result<HttpResponse> {
        tracing::info!(%cache_key, "Populating HTTP cache");
        self.inner.put(cache_key, res, policy).await
    }

    async fn delete(&self, cache_key: &str) -> http_cache::Result<()> {
        tracing::info!(%cache_key, "Removing from HTTP cache");
        self.inner.delete(cache_key).await
    }
}
