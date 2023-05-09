//! Authority struct and functions

use fission_common::authority::key_material::SUPPORTED_KEYS;
use std::time::{SystemTime, UNIX_EPOCH};
use ucan::crypto::did::DidParser;

// 🧬

use fission_common::authority;

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
    pub async fn validate(&self) -> Result<(), authority::Error> {
        let mut did_parser = DidParser::new(SUPPORTED_KEYS);
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|t| t.as_secs());

        ucan::Ucan::validate(&self.ucan, current_time, &mut did_parser)
            .await
            .map_err(|err| authority::Error::InvalidUcan {
                reason: err.to_string(),
            })
    }
}
