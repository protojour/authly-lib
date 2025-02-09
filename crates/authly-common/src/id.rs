//! Authly identifier types
use std::{
    fmt::{Debug, Display},
    hash::Hash,
    marker::PhantomData,
    str::FromStr,
};

use anyhow::{anyhow, Context};
use kind::{IdKind, Kind};
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

    /// Construct a new identifier from a reference to a byte array, without type information
    pub const fn from_raw_array(array: &[u8; 16]) -> Self {
        Self(*array, PhantomData)
    }

    /// Get the byte-wise representation of the ID, without type information
    pub const fn to_raw_array(self) -> [u8; 16] {
        self.0
    }

    /// Try to deserialize from a raw byte representation, without type information
    pub fn from_raw_bytes(bytes: &[u8]) -> Option<Self> {
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

impl<K: IdKind> Display for Id128<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(prefix) = K::kind().str_prefix() {
            write!(f, "{prefix}")?;
        }

        write!(f, "{}", hexhex::hex(&self.0))
    }
}

/// Conversion to and from byte arrays without Kind information.
pub trait Id128StaticArrayConv {
    /// Convert a byte array into this type.
    fn from_array_static(array: &[u8; 16]) -> Self;

    /// Convert this type into a byte array.
    fn to_array_static(&self) -> [u8; 16];
}

/// Conversion to and from byte arrays with Kind information.
pub trait Id128DynamicArrayConv: Sized {
    /// Convert a byte array into this type.
    fn try_from_array_dynamic(array: &[u8; 17]) -> Option<Self>;

    /// Convert a byte slice into this type.
    fn try_from_bytes_dynamic(bytes: &[u8]) -> Option<Self> {
        Self::try_from_array_dynamic(bytes.try_into().ok()?)
    }

    /// Convert this type into a byte array.
    fn to_array_dynamic(&self) -> [u8; 17];
}

/// Types of Kinds of typed Ids.
pub mod kind {
    use int_enum::IntEnum;

    /// A dynamic kind of ID.
    ///
    /// It acts as a "namespace" for identifiers.
    #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, IntEnum, Debug)]
    #[repr(u8)]
    pub enum Kind {
        /// Entity kind.
        Entity = 0,
        /// Domain kind.
        Domain = 1,
        /// Policy kind.
        Policy = 2,
        /// Policy binding kind.
        PolicyBinding = 3,
        /// Property kind.
        Property = 4,
        /// Attribute kind.
        Attribute = 5,
        /// Directory kind.
        Directory = 6,
    }

    impl Kind {
        pub(super) const fn str_prefix(&self) -> Option<&'static str> {
            match self {
                Self::Entity => Some("e."),
                Self::Domain => Some("d."),
                Self::Attribute => Some("a."),
                _ => None,
            }
        }

        pub(super) const fn name(&self) -> &'static str {
            match self {
                Kind::Entity => "entity ID",
                Kind::Domain => "domain ID",
                Kind::Policy => "policy ID",
                Kind::PolicyBinding => "policy binding ID",
                Kind::Property => "property ID",
                Kind::Attribute => "attribute ID",
                Kind::Directory => "directory ID",
            }
        }
    }

    /// Trait for static kinds of Ids.
    pub trait IdKind {
        /// The runtime kind of static ID kind.
        fn kind() -> Kind;
    }

    /// Entity ID kind.
    pub struct Entity;

    /// Domain ID kind.
    pub struct Domain;

    /// Policy ID kind.
    pub struct Policy;

    /// Policy binding ID kind.
    pub struct PolicyBinding;

    /// Attribute ID kind.
    pub struct Property;

    /// Attribute ID kind.
    pub struct Attrbute;

    /// Directory ID kind.
    pub struct Directory;

    impl IdKind for Entity {
        fn kind() -> Kind {
            Kind::Entity
        }
    }

    impl IdKind for Domain {
        fn kind() -> Kind {
            Kind::Domain
        }
    }

    impl IdKind for Policy {
        fn kind() -> Kind {
            Kind::Policy
        }
    }

    impl IdKind for PolicyBinding {
        fn kind() -> Kind {
            Kind::PolicyBinding
        }
    }

    impl IdKind for Property {
        fn kind() -> Kind {
            Kind::Property
        }
    }

    impl IdKind for Attrbute {
        fn kind() -> Kind {
            Kind::Attribute
        }
    }

    impl IdKind for Directory {
        fn kind() -> Kind {
            Kind::Directory
        }
    }
}

/// Authly Entity ID
pub type Eid = Id128<kind::Entity>;

/// Authly Property ID
pub type PropId = Id128<kind::Property>;

/// Authly Attribute ID
pub type AttrId = Id128<kind::Attrbute>;

/// Authly Policy ID
pub type PolicyId = Id128<kind::Policy>;

/// Authly Policy Binding ID
pub type PolicyBindingId = Id128<kind::PolicyBinding>;

/// Authly Domain ID
pub type DomainId = Id128<kind::Domain>;

/// Authly Directory ID
pub type DirectoryId = Id128<kind::Directory>;

/// Dynamically typed ID
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct AnyId {
    id: [u8; 16],
    kind: kind::Kind,
}

impl AnyId {
    /// The dynamic kind of this AnyId.
    pub fn kind(&self) -> Kind {
        self.kind
    }
}

impl<K: IdKind> FromStr for Id128<K> {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let Some(prefix) = K::kind().str_prefix() else {
            return Err(anyhow!(
                "{} cannot be deserialized; no prefix",
                K::kind().name()
            ));
        };
        let Some(s) = s.strip_prefix(prefix) else {
            return Err(anyhow!("unrecognized prefix, expected `{prefix}`"));
        };

        let hex = hexhex::decode(s).context("invalid format")?;
        let array: [u8; 16] = hex.try_into().map_err(|_| anyhow!("invalid length"))?;

        let min = 32768_u128.to_be_bytes();

        if array != [0; 16] && array < min {
            return Err(anyhow!("invalid value, too small"));
        }

        Ok(Id128(array, PhantomData))
    }
}

impl<'de, K: IdKind> Deserialize<'de> for Id128<K> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(FromStrVisitor::new(K::kind().name()))
    }
}

impl<K: IdKind> Serialize for Id128<K> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&format!(
            "{}{}",
            K::kind().str_prefix().unwrap_or(""),
            hexhex::hex(&self.0)
        ))
    }
}

impl<K: IdKind> Id128StaticArrayConv for Id128<K> {
    fn from_array_static(array: &[u8; 16]) -> Self {
        Self::from_raw_array(array)
    }

    fn to_array_static(&self) -> [u8; 16] {
        self.to_raw_array()
    }
}

impl<K: IdKind> Id128DynamicArrayConv for Id128<K> {
    fn try_from_array_dynamic(array: &[u8; 17]) -> Option<Self> {
        let kind_byte: u8 = K::kind().into();
        if array[0] == kind_byte {
            Self::from_raw_bytes(&array[1..])
        } else {
            None
        }
    }

    fn to_array_dynamic(&self) -> [u8; 17] {
        let mut output = [0u8; 17];
        output[0] = K::kind().into();
        output[1..].clone_from_slice(&self.to_raw_array());
        output
    }
}

impl Id128DynamicArrayConv for AnyId {
    fn try_from_array_dynamic(array: &[u8; 17]) -> Option<Self> {
        let kind = Kind::try_from(array[0]).ok()?;
        let id = array[1..].try_into().ok()?;

        Some(Self { kind, id })
    }

    fn to_array_dynamic(&self) -> [u8; 17] {
        let mut output = [0u8; 17];
        output[0] = self.kind.into();
        output[1..].clone_from_slice(&self.id);
        output
    }
}

impl<K: IdKind> From<Id128<K>> for AnyId {
    fn from(value: Id128<K>) -> Self {
        Self {
            kind: K::kind(),
            id: value.0,
        }
    }
}

impl<K: IdKind> TryFrom<AnyId> for Id128<K> {
    type Error = ();

    fn try_from(value: AnyId) -> Result<Self, Self::Error> {
        if value.kind != K::kind() {
            return Err(());
        }

        Ok(Self(value.id, PhantomData))
    }
}

#[test]
fn from_hex_literal() {
    let _ = Eid::from(hexhex::hex_literal!("1234abcd1234abcd1234abcd1234abcd"));
}

#[test]
fn from_str() {
    Eid::from_str("e.1234abcd1234abcd1234abcd1234abcd").unwrap();
    Eid::from_str("d.1234abcd1234abcd1234abcd1234abcd").unwrap_err();
    DomainId::from_str("d.1234abcd1234abcd1234abcd1234abcd").unwrap();
}

#[test]
fn serde() {
    let before = Eid::from_str("e.1234abcd1234abcd1234abcd1234abcd").unwrap();
    let json = serde_json::to_string(&before).unwrap();

    assert_eq!("\"e.1234abcd1234abcd1234abcd1234abcd\"", json);

    let after: Eid = serde_json::from_str(&json).unwrap();

    assert_eq!(before, after);
}
