//! Authly identifier types
use std::{
    fmt::{Debug, Display},
    hash::Hash,
    marker::PhantomData,
    str::FromStr,
};

use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::FromStrVisitor;

/// Authly generic 128-bit identifier
pub struct Id128<K>([u8; 16], PhantomData<K>);

impl<K> Id128<K> {
    /// Construct a new identifier from a 128-bit unsigned int.
    pub const fn from_uint(val: u128) -> Self {
        Self(val.to_be_bytes(), PhantomData)
    }

    /// Construct a new identifier from a reference to a byte array.
    pub const fn from_array(array: &[u8; 16]) -> Self {
        Self(*array, PhantomData)
    }

    /// Get the byte-wise representation of the ID.
    pub const fn to_bytes(self) -> [u8; 16] {
        self.0
    }

    /// Try to deserialize from a byte representation.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        Some(Self(bytes.try_into().ok()?, PhantomData))
    }

    /// Create a new random identifier.
    pub fn random() -> Self {
        loop {
            let id: u128 = rand::thread_rng().gen();
            // low IDs are reserved for builtin/fixed
            if id > u16::MAX as u128 {
                return Self(id.to_be_bytes(), PhantomData);
            }
        }
    }

    /// Convert typed ID to [AnyId].
    pub const fn to_any(&self) -> AnyId {
        Id128(self.0, PhantomData)
    }

    /// Convert to an unsigned integer
    pub fn to_uint(&self) -> u128 {
        u128::from_be_bytes(self.0)
    }
}

impl<K> Clone for Id128<K> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<K> Copy for Id128<K> {}

impl<K> PartialEq for Id128<K> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<K> Eq for Id128<K> {}

impl<K> PartialOrd<Id128<K>> for Id128<K> {
    fn partial_cmp(&self, other: &Id128<K>) -> Option<std::cmp::Ordering> {
        Some(self.0.cmp(&other.0))
    }
}

impl<K> Ord for Id128<K> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl<K> Hash for Id128<K> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl<K> From<[u8; 16]> for Id128<K> {
    fn from(value: [u8; 16]) -> Self {
        Self(value, PhantomData)
    }
}

impl<K> From<&[u8; 16]> for Id128<K> {
    fn from(value: &[u8; 16]) -> Self {
        Self(*value, PhantomData)
    }
}

impl<K> Debug for Id128<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hexhex::hex(&self.0))
    }
}

impl<K> Display for Id128<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hexhex::hex(&self.0))
    }
}

/// Kinds of typed Ids.
pub mod idkind {
    /// Trait for kinds of Ids.
    pub trait IdKind {
        /// The name of the id kind.
        fn name() -> &'static str;
    }

    /// Entity ID kind.
    pub struct Entity;

    /// Object ID kind.
    pub struct Object;

    /// Any ID kind.
    pub struct Any;

    impl IdKind for Entity {
        fn name() -> &'static str {
            "entity id"
        }
    }

    impl IdKind for Object {
        fn name() -> &'static str {
            "entity id"
        }
    }

    impl IdKind for Any {
        fn name() -> &'static str {
            "any id"
        }
    }
}

/// Authly Entity ID
pub type Eid = Id128<idkind::Entity>;

/// Authly Object ID
pub type ObjId = Id128<idkind::Object>;

/// Untyped ID
pub type AnyId = Id128<idkind::Any>;

impl<K> FromStr for Id128<K> {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let hex = hexhex::decode(s).map_err(|_| "invalid format")?;
        let array: [u8; 16] = hex.try_into().map_err(|_| "invalid length")?;

        let min = 32768_u128.to_be_bytes();

        if array != [0; 16] && array < min {
            return Err("invalid value");
        }

        Ok(Id128(array, PhantomData))
    }
}

impl<'de, K: idkind::IdKind> Deserialize<'de> for Id128<K> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(FromStrVisitor::new(K::name()))
    }
}

impl<K> Serialize for Id128<K> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&hexhex::hex(&self.0).to_string())
    }
}

#[test]
fn from_hex_literal() {
    let _ = AnyId::from(hexhex::hex_literal!("1234abcd1234abcd1234abcd1234abcd"));
}
