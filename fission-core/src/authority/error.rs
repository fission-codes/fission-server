//! Authority error type and implementations

///////////
// TYPES //
///////////

#[derive(Debug)]
/// Implements https://github.com/ucan-wg/ucan-as-bearer-token#33-errors
pub enum Error {
    /// UCAN does not include sufficient authority to perform the requestor's action
    InsufficientCapabilityScope,

    /// UCAN is expired, revoked, malformed, or otherwise invalid
    InvalidUcan {
        /// Reason why the UCAN is invalid
        reason: String,
    },

    /// UCAN is missing
    MissingCredentials,

    /// Referenced proofs are missing from the cache
    MissingProofs {
        /// The CIDs of the proofs that are missing
        proofs_needed: Vec<String>,
    },
}
