//! Authly property utilities.
use std::str::FromStr;

use serde::Deserialize;

use crate::FromStrVisitor;

/// A qualified attribute name, in the context of a service.
///
/// Consists of a property and an attribute of that property.
#[derive(Debug)]
pub struct QualifiedAttributeName {
    /// The namespace
    pub namespace: String,

    /// The property name.
    pub property: String,

    /// The attribute name.
    pub attribute: String,
}

impl FromStr for QualifiedAttributeName {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut segments = s.split(":");
        let namespace = segments.next();
        let property = segments.next();
        let attribute = segments.next();

        match (namespace, property, attribute) {
            (Some(namespace), Some(property), Some(attribute)) => Ok(Self {
                namespace: namespace.to_string(),
                property: property.to_string(),
                attribute: attribute.to_string(),
            }),
            _ => Err("expected qualified namespace/property/attribute triple"),
        }
    }
}

impl<'de> Deserialize<'de> for QualifiedAttributeName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(FromStrVisitor::new("attribute name"))
    }
}
