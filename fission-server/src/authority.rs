//! Authority struct and functions

use fission_core::authority::key_material::SUPPORTED_KEYS;
use std::time::{SystemTime, UNIX_EPOCH};
use ucan::crypto::did::DidParser;

///////////
// TYPES //
///////////

#[derive(Debug)]
/// Represents the authority of an incoming request
pub struct Authority {
    /// https://github.com/ucan-wg/ucan-as-bearer-token#21-entry-point
    pub ucan: ucan::Ucan,
}

/////////////////////
// IMPLEMENTATIONS //
/////////////////////

impl Authority {
    /// Validate an authority struct
    pub async fn validate(&self) -> Result<(), String> {
        let mut did_parser = DidParser::new(SUPPORTED_KEYS);
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|t| t.as_secs());

        ucan::Ucan::validate(&self.ucan, current_time, &mut did_parser)
            .await
            .map_err(|err| err.to_string())
    }
}

///////////
// TESTS //
///////////

#[cfg(test)]
mod tests {
    use super::*;
    use fission_core::authority::key_material::{generate_ed25519_material, SERVER_DID};
    use ucan::builder::UcanBuilder;

    #[tokio::test]
    async fn validation_test() {
        let issuer = generate_ed25519_material();
        let ucan = UcanBuilder::default()
            .issued_by(&issuer)
            .for_audience(SERVER_DID)
            .with_lifetime(100)
            .build()
            .unwrap()
            .sign()
            .await
            .unwrap();

        let authority = Authority { ucan };

        assert!(authority.validate().await.is_ok());
    }
}
