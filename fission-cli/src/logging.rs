use anyhow::anyhow;
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
