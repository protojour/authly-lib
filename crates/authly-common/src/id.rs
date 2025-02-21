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
use subset::{IdKindSubset, IdKindSupersetOf};

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

impl<K: IdKind> Id128<K> {
    /// Infallibly convert this into a [DynamicId]
    pub fn upcast<KS: IdKindSubset + IdKindSupersetOf<K>>(self) -> DynamicId<KS> {
        DynamicId {
            id: self.0,
            kind: K::kind(),
            _subset: PhantomData,
        }
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
        write!(f, "{}.{}", K::kind().str_prefix(), hexhex::hex(&self.0))
    }
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
    use serde::{Deserialize, Serialize};

    /// A dynamic kind of ID.
    ///
    /// It acts as a "namespace" for identifiers.
    ///
    /// NB: This enum is used in persisted postcard serializations, new variants should be added at the end!
    #[derive(
        Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, IntEnum, Serialize, Deserialize, Debug,
    )]
    #[repr(u8)]
    pub enum Kind {
        /// Persona Entity kind.
        Persona = 0,
        /// Group Entity kind.
        Group = 1,
        /// Service Entity kind.
        Service = 2,
        /// Domain kind.
        Domain = 3,
        /// Policy kind.
        Policy = 4,
        /// Property kind.
        Property = 5,
        /// Attribute kind.
        Attribute = 6,
        /// Directory kind.
        Directory = 7,
    }

    impl Kind {
        #[inline]
        pub(super) const fn str_prefix(&self) -> &'static str {
            match self {
                Self::Persona => "p",
                Self::Group => "g",
                Self::Service => "s",
                Self::Domain => "d",
                Self::Property => "prp",
                Self::Attribute => "atr",
                Self::Directory => "dir",
                Self::Policy => "pol",
            }
        }

        pub(super) const fn name(&self) -> &'static str {
            match self {
                Kind::Persona => "persona ID",
                Kind::Group => "group ID",
                Kind::Service => "service ID",
                Kind::Domain => "domain ID",
                Kind::Policy => "policy ID",
                Kind::Property => "property ID",
                Kind::Attribute => "attribute ID",
                Kind::Directory => "directory ID",
            }
        }

        pub(super) const fn entries() -> &'static [Self] {
            &[
                Self::Persona,
                Self::Group,
                Self::Service,
                Self::Domain,
                Self::Policy,
                Self::Property,
                Self::Attribute,
                Self::Directory,
            ]
        }
    }

    /// Trait for static kinds of Ids.
    pub trait IdKind {
        /// The runtime kind of static ID kind.
        fn kind() -> Kind;
    }

    /// Persona ID kind.
    pub struct Persona;

    /// Group ID kind.
    pub struct Group;

    /// Service ID kind.
    pub struct Service;

    /// Domain ID kind.
    pub struct Domain;

    /// Policy ID kind.
    pub struct Policy;

    /// Attribute ID kind.
    pub struct Property;

    /// Attribute ID kind.
    pub struct Attrbute;

    /// Directory ID kind.
    pub struct Directory;

    impl IdKind for Persona {
        fn kind() -> Kind {
            Kind::Persona
        }
    }

    impl IdKind for Group {
        fn kind() -> Kind {
            Kind::Group
        }
    }

    impl IdKind for Service {
        fn kind() -> Kind {
            Kind::Service
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

/// Id kind subsets.
pub mod subset {
    use super::kind::{Group, IdKind, Kind, Persona, Service};

    /// Describes a specific subset of Authly ID kinds.
    pub trait IdKindSubset {
        /// Whether the subset contains the given [Kind].
        fn contains(kind: Kind) -> bool;

        /// The name of this subset.
        fn name() -> &'static str;
    }

    /// Describes a specific _superset_ of K.
    pub trait IdKindSupersetOf<K> {}

    /// The Entity subset.
    pub struct Entity;

    /// The Any subset, which contains all kinds of Authly IDs.
    pub struct Any;

    impl IdKindSubset for Entity {
        fn contains(kind: Kind) -> bool {
            matches!(kind, Kind::Persona | Kind::Group | Kind::Service)
        }

        fn name() -> &'static str {
            "Entity ID"
        }
    }

    impl IdKindSupersetOf<Persona> for Entity {}
    impl IdKindSupersetOf<Group> for Entity {}
    impl IdKindSupersetOf<Service> for Entity {}

    impl IdKindSubset for Any {
        fn contains(_kind: Kind) -> bool {
            true
        }

        fn name() -> &'static str {
            "Any ID"
        }
    }

    impl<K: IdKind> IdKindSupersetOf<K> for Any {}
    impl IdKindSupersetOf<Entity> for Any {}
}

/// Authly Persona ID
pub type PersonaId = Id128<kind::Persona>;

/// Authly Group ID
pub type GroupId = Id128<kind::Group>;

/// Authly Service ID
pub type ServiceId = Id128<kind::Service>;

/// Authly Property ID
pub type PropId = Id128<kind::Property>;

/// Authly Attribute ID
pub type AttrId = Id128<kind::Attrbute>;

/// Authly Policy ID
pub type PolicyId = Id128<kind::Policy>;

/// Authly Domain ID
pub type DomainId = Id128<kind::Domain>;

/// Authly Directory ID
pub type DirectoryId = Id128<kind::Directory>;

/// Dynamically typed ID, can represent any kind "object" Id
pub struct DynamicId<KS: IdKindSubset> {
    pub(crate) id: [u8; 16],
    kind: kind::Kind,
    _subset: PhantomData<KS>,
}

impl<KS: IdKindSubset> DynamicId<KS> {
    /// Construct a new dynamicId.
    ///
    /// Panics if [Kind] is not member of the KS subset.
    pub fn new(kind: Kind, id: [u8; 16]) -> Self {
        if !KS::contains(kind) {
            panic!("Not in subset");
        }
        Self {
            kind,
            id,
            _subset: PhantomData,
        }
    }

    /// The dynamic kind of this dynamic id.
    pub fn kind(&self) -> Kind {
        self.kind
    }

    /// Infallibly upcast this into a superset [DynamicId].
    pub fn upcast<KS2: IdKindSubset + IdKindSupersetOf<KS>>(&self) -> DynamicId<KS2> {
        DynamicId {
            id: self.id,
            kind: self.kind,
            _subset: PhantomData,
        }
    }

    /// Get the byte-wise representation of the ID, without type information.
    /// NB! This erases the dynamic tag!
    pub const fn to_raw_array(self) -> [u8; 16] {
        self.id
    }
}

impl<KS: IdKindSubset> Clone for DynamicId<KS> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<KS: IdKindSubset> Copy for DynamicId<KS> {}

impl<KS: IdKindSubset> Debug for DynamicId<KS> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.kind.str_prefix(), hexhex::hex(&self.id))
    }
}

impl<KS: IdKindSubset> Display for DynamicId<KS> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.kind.str_prefix(), hexhex::hex(&self.id))
    }
}

impl<KS: IdKindSubset> PartialEq for DynamicId<KS> {
    fn eq(&self, other: &Self) -> bool {
        self.kind == other.kind && self.id == other.id
    }
}

impl<KS: IdKindSubset> Eq for DynamicId<KS> {}

impl<KS: IdKindSubset> Hash for DynamicId<KS> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
        self.kind.hash(state);
    }
}

impl<KS: IdKindSubset> PartialOrd<DynamicId<KS>> for DynamicId<KS> {
    fn partial_cmp(&self, other: &DynamicId<KS>) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<KS: IdKindSubset> Ord for DynamicId<KS> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.kind
            .cmp(&other.kind)
            .then_with(|| self.id.cmp(&other.id))
    }
}

/// An Authly Entity ID.
pub type EntityId = DynamicId<subset::Entity>;

/// An Authly Any Id - the Id of any object, entities or other objects.
pub type AnyId = DynamicId<subset::Any>;

impl<K: IdKind> FromStr for Id128<K> {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let prefix = K::kind().str_prefix();
        let Some(s) = s.strip_prefix(prefix) else {
            return Err(anyhow!("unrecognized prefix, expected `{prefix}`"));
        };
        let s = s.strip_prefix('.').context("missing `.`")?;

        let hex = hexhex::decode(s).context("invalid format")?;
        let array: [u8; 16] = hex.try_into().map_err(|_| anyhow!("invalid length"))?;

        let min = 32768_u128.to_be_bytes();

        if array != [0; 16] && array < min {
            return Err(anyhow!("invalid value, too small"));
        }

        Ok(Id128(array, PhantomData))
    }
}

impl<S: IdKindSubset> FromStr for DynamicId<S> {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut segments = s.splitn(2, ".");
        let prefix = segments.next().context("no prefix")?;
        let s = segments.next().context("no hex code")?;

        if segments.next().is_some() {
            return Err(anyhow!("too many dots"));
        }

        let kind = Kind::entries()
            .iter()
            .copied()
            .find(|kind| kind.str_prefix() == prefix)
            .context("unrecognized prefix")?;

        if !S::contains(kind) {
            return Err(anyhow!("invalid subset"));
        }

        let hex = hexhex::decode(s).context("invalid format")?;
        let array: [u8; 16] = hex.try_into().map_err(|_| anyhow!("invalid length"))?;

        let min = 32768_u128.to_be_bytes();

        if array != [0; 16] && array < min {
            return Err(anyhow!("invalid value, too small"));
        }

        Ok(DynamicId {
            id: array,
            kind,
            _subset: PhantomData,
        })
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
            "{}.{}",
            K::kind().str_prefix(),
            hexhex::hex(&self.0)
        ))
    }
}

impl<KS: IdKindSubset> Serialize for DynamicId<KS> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&format!(
            "{}.{}",
            self.kind.str_prefix(),
            hexhex::hex(&self.id)
        ))
    }
}

impl<'de, KS: IdKindSubset> Deserialize<'de> for DynamicId<KS> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(FromStrVisitor::new(KS::name()))
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

impl<KS: IdKindSubset> Id128DynamicArrayConv for DynamicId<KS> {
    fn try_from_array_dynamic(array: &[u8; 17]) -> Option<Self> {
        let kind = Kind::try_from(array[0]).ok()?;
        if !KS::contains(kind) {
            return None;
        }

        let id = array[1..].try_into().ok()?;

        Some(Self {
            kind,
            id,
            _subset: PhantomData,
        })
    }

    fn to_array_dynamic(&self) -> [u8; 17] {
        let mut output = [0u8; 17];
        output[0] = self.kind.into();
        output[1..].clone_from_slice(&self.id);
        output
    }
}

impl<K: IdKind, KS: IdKindSubset> TryFrom<Id128<K>> for DynamicId<KS> {
    type Error = ();

    fn try_from(value: Id128<K>) -> Result<Self, Self::Error> {
        if KS::contains(K::kind()) {
            Ok(Self {
                kind: K::kind(),
                id: value.0,
                _subset: PhantomData,
            })
        } else {
            Err(())
        }
    }
}

impl<K: IdKind, KS: IdKindSubset> TryFrom<DynamicId<KS>> for Id128<K> {
    type Error = ();

    fn try_from(value: DynamicId<KS>) -> Result<Self, Self::Error> {
        if value.kind != K::kind() {
            return Err(());
        }

        Ok(Self(value.id, PhantomData))
    }
}

#[test]
fn from_hex_literal() {
    let _ = PersonaId::from(hexhex::hex_literal!("1234abcd1234abcd1234abcd1234abcd"));
}

#[test]
fn from_str() {
    PersonaId::from_str("p.1234abcd1234abcd1234abcd1234abcd").unwrap();
    ServiceId::from_str("s.1234abcd1234abcd1234abcd1234abcd").unwrap();
    PersonaId::from_str("d.1234abcd1234abcd1234abcd1234abcd").unwrap_err();
    DomainId::from_str("d.1234abcd1234abcd1234abcd1234abcd").unwrap();

    AnyId::from_str("s.1234abcd1234abcd1234abcd1234abcd").unwrap();
    AnyId::from_str("d.1234abcd1234abcd1234abcd1234abcd").unwrap();
    EntityId::from_str("s.1234abcd1234abcd1234abcd1234abcd").unwrap();
    EntityId::from_str("g.1234abcd1234abcd1234abcd1234abcd").unwrap();
    EntityId::from_str("d.1234abcd1234abcd1234abcd1234abcd").unwrap_err();
}

#[test]
fn serde() {
    let before = PersonaId::from_str("p.1234abcd1234abcd1234abcd1234abcd").unwrap();
    let json = serde_json::to_string(&before).unwrap();

    assert_eq!("\"p.1234abcd1234abcd1234abcd1234abcd\"", json);

    let after: PersonaId = serde_json::from_str(&json).unwrap();

    assert_eq!(before, after);
}
