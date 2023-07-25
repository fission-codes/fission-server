use async_trait::async_trait;
use tokio::sync::broadcast;

use crate::app_state::VerificationCodeSender;

pub(crate) mod test_context;

#[derive(Debug, Clone, Default)]
pub(crate) struct MockVerificationCodeSender;

#[async_trait]
impl VerificationCodeSender for MockVerificationCodeSender {
    async fn send_code(&self, _email: &str, _code: &str) -> anyhow::Result<()> {
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub(crate) struct BroadcastVerificationCodeSender(pub(crate) broadcast::Sender<(String, String)>);

#[async_trait]
impl VerificationCodeSender for BroadcastVerificationCodeSender {
    async fn send_code(&self, email: &str, code: &str) -> anyhow::Result<()> {
        self.0.send((email.to_string(), code.to_string()))?;

        Ok(())
    }
}
