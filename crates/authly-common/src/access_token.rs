//! Types defining authly access token.

use fnv::FnvHashSet;
use serde::{Deserialize, Serialize};

use crate::id::{AttrId, EntityId};

/// Claims for the Authly Access Token JWT
#[derive(Serialize, Deserialize, Debug)]
pub struct AuthlyAccessTokenClaims {
    /// Issued at.
    ///
    /// Authly may publish a Reset event which invalidates all tokens issued in the past.
    pub iat: i64,

    /// Expiration time
    pub exp: i64,

    /// Authy claims
    pub authly: Authly,
}

/// The authly claim.
#[derive(Serialize, Deserialize, Debug)]
pub struct Authly {
    /// The [EntityId] of the entity the access token was issued for.
    pub entity_id: EntityId,

    /// The entity attributes at the time the token was issued.
    pub entity_attributes: FnvHashSet<AttrId>,
}
