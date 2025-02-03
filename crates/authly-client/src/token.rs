//! Token utilities.

use authly_common::access_token::AuthlyAccessTokenClaims;

/// A verified access token, both in encoded and decoded format.
pub struct AccessToken {
    /// The access token in JWT format
    pub token: String,

    /// The decoded/verified token claims
    pub claims: AuthlyAccessTokenClaims,
}
