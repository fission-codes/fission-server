//! DID resource

use anyhow::{anyhow, Result};
use ucan::capability::Scope;
use url::Url;

//////////////
// RESOURCE //
//////////////

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
pub struct Resource {
    pub did: String,
}

impl Scope for Resource {
    fn contains(&self, other: &Self) -> bool {
        other.did == self.did
    }
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
