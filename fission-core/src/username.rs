//! Usernames and Handles

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use utoipa::ToSchema;
use validator::{Validate, ValidationError, ValidationErrors};

/// A verified username.
///
/// This doesn't include the domain portion.
/// A struct representing that would be `Handle`.
///
/// Unicode is represented as punycode in this case.
///
/// Usernames have a 63 byte limit (in punycode encoding)
/// due to inherent limits in the DNS protocol.
///
/// The `Display` instance and `from_unicode` function work
/// with unicode, everything else works with the encoded
/// punycode variants.
#[derive(Clone, ToSchema, Serialize, Deserialize, Validate, Eq, PartialEq, PartialOrd, Ord)]
#[serde(transparent)]
pub struct Username {
    #[validate(length(min = 1, max = 63))]
    #[validate(custom = "valid_domain_encoding")]
    #[validate(custom = "first_character_restrictions")]
    inner: String,
}

impl std::fmt::Debug for Username {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Username").field(&self.inner).finish()
    }
}

impl AsRef<str> for Username {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl std::fmt::Display for Username {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.as_str().fmt(f)
    }
}

impl FromStr for Username {
    type Err = ValidationErrors;

    fn from_str(s: &str) -> Result<Self, ValidationErrors> {
        let username = Self {
            inner: s.to_string(),
        };
        username.validate()?;
        Ok(username)
    }
}

impl Username {
    /// Try to turn a unicode username
    pub fn from_unicode(s: &str) -> Result<Self> {
        let inner = idna::domain_to_ascii(s)?;
        let username = Self { inner };
        username.validate()?;
        Ok(username)
    }

    /// Get a string reference of this username.
    /// This will give you the punycode variant.
    pub fn as_str(&self) -> &str {
        self.inner.as_str()
    }

    /// Get this username as a unicode string
    pub fn to_unicode(&self) -> String {
        idna::domain_to_unicode(self.as_str()).0
    }
}

/// A verified handle.
///
/// This is a full username containing the name portion
/// and any domains (e.g. `matheus23.fission.name`).
///
/// It's only deemed valid if <= 220 bytes, to leave space
/// potential subdomain records needed such as e.g.
/// `_did.` (`_did.matheus23.fission.name`) and any future ones.
///
/// If unicode is needed, use punycode for internationalized
/// domain names (IDNs).
///
/// The length limit is determined in the punycode-encoded variant.
#[derive(Clone, ToSchema, Serialize, Deserialize, Validate, Eq, PartialEq, PartialOrd, Ord)]
#[serde(transparent)]
pub struct Handle {
    #[validate(length(min = 1, max = 220))]
    #[validate(custom = "valid_domain_encoding")]
    inner: String,
}

impl std::fmt::Debug for Handle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Handle").field(&self.as_str()).finish()
    }
}

impl std::fmt::Display for Handle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.as_str().fmt(f)
    }
}

impl FromStr for Handle {
    type Err = ValidationErrors;

    fn from_str(s: &str) -> Result<Self, ValidationErrors> {
        let handle = Self {
            inner: s.to_string(),
        };
        handle.validate()?;
        Ok(handle)
    }
}

impl Handle {
    /// Return a handle as a string reference in punycode format
    pub fn as_str(&self) -> &str {
        self.inner.as_str()
    }

    /// Construct a handle from a username & domain
    pub fn new(username: &str, domain: &str) -> Result<Self> {
        Ok(Self::from_str(&format!("{username}.{domain}"))?)
    }

    /// Get this handle as a unicode string
    pub fn to_unicode(&self) -> String {
        idna::domain_to_unicode(self.as_str()).0
    }
}

fn valid_domain_encoding(s: &str) -> Result<(), ValidationError> {
    let err = ValidationError::new("unsuitable for encoding in domain names");

    let (unicode, errs) = idna::domain_to_unicode(s);
    errs.map_err(|_| err.clone())?;

    let result = idna::domain_to_ascii_strict(&unicode).map_err(|_| err.clone())?;

    if s != result {
        return Err(err);
    }

    Ok(())
}

fn first_character_restrictions(s: &str) -> Result<(), ValidationError> {
    let disallowed_first = ['_', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'];

    if disallowed_first.iter().any(|needle| s.starts_with(*needle)) {
        Err(ValidationError::new(
            "underscores or numbers are disallowed in the first character",
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;

    #[test]
    fn test_username_too_long() {
        assert_matches!(
            "x2x4x6x810121416182022242628303234363840424446485052545658606264".parse::<Username>(),
            Err(_)
        );
    }

    #[test]
    fn test_username_length_limit() {
        assert_matches!(
            "xx3x5x7x9111315171921232527293133353739414345474951535557596163".parse::<Username>(),
            Ok(_)
        );
    }

    #[test]
    fn test_username_invalid_characters() {
        assert_matches!("this has spaces".parse::<Username>(), Err(_));
        assert_matches!("Ümlaute".parse::<Username>(), Err(_));
        assert_matches!("anyUppercase".parse::<Username>(), Err(_));
    }

    #[test]
    fn test_username_invalid_first_characters() {
        assert_matches!("1_starts_with_numbers".parse::<Username>(), Err(_));
        assert_matches!("_starts_with_underscore".parse::<Username>(), Err(_));
    }

    #[test]
    fn test_valid_usernames() {
        assert_matches!("name".parse::<Username>(), Ok(_));
        assert_matches!("alice".parse::<Username>(), Ok(_));
        assert_matches!("bob".parse::<Username>(), Ok(_));
        assert_matches!("bob22".parse::<Username>(), Ok(_));
    }

    #[test]
    fn test_punycode_valid() {
        assert_matches!(Username::from_unicode("bücher"), Ok(_));
        assert_matches!(Username::from_unicode("ひらがな"), Ok(_));
    }

    #[test]
    fn test_punycode_invvalid() {
        assert_matches!(Username::from_unicode("Max Müller"), Err(_)); // has a space
        assert_matches!(Username::from_unicode("_ひらがな"), Err(_)); // starts with underscore
    }
}
