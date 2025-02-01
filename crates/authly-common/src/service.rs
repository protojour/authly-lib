//! Authly service utilities and helpers

use std::collections::{hash_map, HashMap};

use fnv::FnvHashSet;

use crate::id::{AnyId, ObjId};

/// A namespaced property mapping maps human-readable property and attribute labels to [ObjId]s.
#[derive(Clone, Default)]
pub struct NamespacePropertyMapping {
    namespaces: HashMap<String, PropertyMappings>,
}

/// A property mapping maps human-readable property and attribute labels to [ObjId]s.
#[derive(Clone, Default)]
pub struct PropertyMappings {
    properties: HashMap<String, AttributeMappings>,
}

/// Attribute mappings for a property.
#[derive(Clone, Default)]
pub struct AttributeMappings {
    attributes: HashMap<String, ObjId>,
}

impl NamespacePropertyMapping {
    /// Get a mutable reference to the namespace
    pub fn namespace_mut(&mut self, namespace_label: String) -> &mut PropertyMappings {
        self.namespaces.entry(namespace_label).or_default()
    }

    /// Get the object ID of a single property/attribute label pair, if found.
    pub fn attribute_object_id(
        &self,
        namespace_label: &str,
        property_label: &str,
        attribute_label: &str,
    ) -> Option<ObjId> {
        self.namespaces
            .get(namespace_label)?
            .properties
            .get(property_label)?
            .attributes
            .get(attribute_label)
            .cloned()
    }

    /// Translate the given namespace/property/attribute labels to underlying [ObjId]s.
    pub fn translate<'a>(
        &self,
        attributes: impl IntoIterator<Item = (&'a str, &'a str, &'a str)>,
    ) -> FnvHashSet<AnyId> {
        let mut output = FnvHashSet::default();
        for (namespace, prop, attr) in attributes {
            let Some(prop_mappings) = self.namespaces.get(namespace) else {
                continue;
            };
            let Some(attr_mappings) = prop_mappings.properties.get(prop) else {
                continue;
            };
            let Some(attr_id) = attr_mappings.attributes.get(attr) else {
                continue;
            };

            output.insert(attr_id.to_any());
        }

        output
    }
}

impl PropertyMappings {
    /// Get a mutable reference to the attribute mappings of a property.
    pub fn property_mut(&mut self, property_label: String) -> &mut AttributeMappings {
        self.properties.entry(property_label).or_default()
    }
}

impl AttributeMappings {
    /// Put a new attribute id under the attribute label.
    pub fn put(&mut self, attribute_label: String, attribute_id: ObjId) {
        self.attributes
            .entry(attribute_label)
            .insert_entry(attribute_id);
    }
}

impl IntoIterator for NamespacePropertyMapping {
    type IntoIter = hash_map::IntoIter<String, PropertyMappings>;
    type Item = (String, PropertyMappings);

    fn into_iter(self) -> Self::IntoIter {
        self.namespaces.into_iter()
    }
}

impl<'a> IntoIterator for &'a NamespacePropertyMapping {
    type IntoIter = hash_map::Iter<'a, String, PropertyMappings>;
    type Item = (&'a String, &'a PropertyMappings);

    fn into_iter(self) -> Self::IntoIter {
        self.namespaces.iter()
    }
}

impl IntoIterator for PropertyMappings {
    type IntoIter = hash_map::IntoIter<String, AttributeMappings>;
    type Item = (String, AttributeMappings);

    fn into_iter(self) -> Self::IntoIter {
        self.properties.into_iter()
    }
}

impl<'a> IntoIterator for &'a PropertyMappings {
    type IntoIter = hash_map::Iter<'a, String, AttributeMappings>;
    type Item = (&'a String, &'a AttributeMappings);

    fn into_iter(self) -> Self::IntoIter {
        self.properties.iter()
    }
}

impl IntoIterator for AttributeMappings {
    type IntoIter = hash_map::IntoIter<String, ObjId>;
    type Item = (String, ObjId);

    fn into_iter(self) -> Self::IntoIter {
        self.attributes.into_iter()
    }
}

impl<'a> IntoIterator for &'a AttributeMappings {
    type IntoIter = hash_map::Iter<'a, String, ObjId>;
    type Item = (&'a String, &'a ObjId);

    fn into_iter(self) -> Self::IntoIter {
        self.attributes.iter()
    }
}
