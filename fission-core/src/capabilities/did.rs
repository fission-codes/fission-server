//! DID Capabilities

use rs_ucan::semantics::resource::Resource;
use std::fmt::Display;

#[derive(Clone, Debug)]
/// DID Resource
pub struct Did(pub String);

impl Resource for Did {
    fn is_valid_attenuation(&self, other: &dyn Resource) -> bool {
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
