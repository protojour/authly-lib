//! Authly Certificate extensions

/// x509 Object Identifier extension
pub mod oid {
    /// Represents the entity ID of Authly services.
    ///
    /// reference: [iod-base.com](https://oid-base.com/get/2.5.4.45)
    pub const ENTITY_UNIQUE_IDENTIFIER: &[u64] = &[2, 5, 4, 45];
}
