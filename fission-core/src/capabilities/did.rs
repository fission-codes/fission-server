//! DID Capabilities

use rs_ucan::{plugins::ucan::UcanResource, semantics::resource::Resource};
use std::fmt::Display;
use url::Url;

/// DID Resource
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Did(pub String);

impl Did {
    /// Try to parse a DID from a resource URI.
    ///
    /// Only `did:key`s are supported at the moment.
    pub fn try_handle_as_resource(uri: &Url) -> Option<Self> {
        let did = uri.as_str();

        if !did.starts_with("did:key:") {
            return None;
        }

        Some(Self(did.to_string()))
    }
}

impl Resource for Did {
    fn is_valid_attenuation(&self, other: &dyn Resource) -> bool {
        if let Some(UcanResource::AllProvable) = other.downcast_ref() {
            return true;
        }

        let Some(Did(did)) = other.downcast_ref() else {
            return false;
        };

        &self.0 == did
    }
}

impl Display for Did {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl AsRef<str> for Did {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}
