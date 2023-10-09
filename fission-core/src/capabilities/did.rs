//! DID Capabilities

use anyhow::{anyhow, Result};
use url::Url;

//////////////
// RESOURCE //
//////////////

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
/// DID Resource
pub struct Resource {
    /// The DID related to the resource
    pub did: String,
}

impl ToString for Resource {
    fn to_string(&self) -> String {
        self.did.clone()
    }
}

impl TryFrom<Url> for Resource {
    type Error = anyhow::Error;

    fn try_from(value: Url) -> Result<Self> {
        match value.scheme() {
            "did" => Ok(Resource {
                did: format!("did:{}", value.path()),
            }),
            _ => Err(anyhow!(
                "Could not interpret URI as a DID resource: {:?}",
                value
            )),
        }
    }
}
