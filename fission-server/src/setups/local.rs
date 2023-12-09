//! Server setup for local development & easier integration testing

use anyhow::Result;
use async_trait::async_trait;
use axum::extract::ws::Message;

use super::{prod::IpfsHttpApiDatabase, ServerSetup, VerificationCodeSender};
use crate::routes::ws::WsPeerMap;
use std::sync::Arc;

/// Implementation of `ServerSetup` for local environments.
/// This allows you to
#[derive(Debug, Clone)]
pub struct LocalSetup;

impl ServerSetup for LocalSetup {
    type IpfsDatabase = IpfsHttpApiDatabase;
    type VerificationCodeSender = WebsocketCodeSender;
}

/// A `VerificationCodeSender` that doesn't actually send emails,
/// but instead logs them via tracing & sends a ws message on the
/// channel with the email as the topic.
#[derive(Debug, Clone)]
pub struct WebsocketCodeSender {
    ws_peer_map: Arc<WsPeerMap>,
}

impl WebsocketCodeSender {
    /// Create a new websocket code sender
    pub fn new(ws_peer_map: Arc<WsPeerMap>) -> Self {
        Self { ws_peer_map }
    }
}

#[async_trait]
impl VerificationCodeSender for WebsocketCodeSender {
    async fn send_code(&self, email: &str, code: &str) -> Result<()> {
        tracing::info!(email, ?code, "verification code (also sent via websockets)");
        self.ws_peer_map
            .broadcast_on_topic(email, Message::Text(code.to_string()), None);
        Ok(())
    }
}
