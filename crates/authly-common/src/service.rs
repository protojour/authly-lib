//! Authly service utilities and helpers

use std::collections::{hash_map, HashMap};

use fnv::FnvHashSet;

use crate::id::AttrId;

/// A namespaced property mapping maps human-readable property and attribute labels to [AttrId]s.
#[derive(Clone, Default)]
pub struct NamespacePropertyMapping {
    namespaces: HashMap<String, PropertyMappings>,
}

/// A property mapping maps human-readable property and attribute labels to [AttrId]s.
#[derive(Clone, Default)]
pub struct PropertyMappings {
    properties: HashMap<String, AttributeMappings>,
}

/// Attribute mappings for a property.
#[derive(Clone, Default)]
pub struct AttributeMappings {
    attributes: HashMap<String, AttrId>,
}

/// A trait describing a namespaced attribute.
pub trait NamespacedPropertyAttribute {
    /// The namespace label of the attribute
    fn namespace(&self) -> &str;

    /// The property label of the attribute
    fn property(&self) -> &str;

    /// The attribute of the namespaced property
    fn attribute(&self) -> &str;
}

impl<'a> NamespacedPropertyAttribute for (&'a str, &'a str, &'a str) {
    fn namespace(&self) -> &str {
        self.0
    }

    fn property(&self) -> &str {
        self.1
    }

    fn attribute(&self) -> &str {
        self.2
    }
}

impl NamespacePropertyMapping {
    /// Get a mutable reference to the namespace
    pub fn namespace_mut(&mut self, namespace_label: String) -> &mut PropertyMappings {
        self.namespaces.entry(namespace_label).or_default()
    }

    /// Get the object ID of a single property/attribute label pair, if found.
    pub fn attribute_object_id(&self, attr: impl NamespacedPropertyAttribute) -> Option<AttrId> {
        self.namespaces
            .get(attr.namespace())?
            .properties
            .get(attr.property())?
            .attributes
            .get(attr.attribute())
            .cloned()
    }

    /// Translate the given namespace/property/attribute labels to underlying [AttrId]s.
    pub fn translate<'a>(
        &self,
        attributes: impl IntoIterator<Item = (&'a str, &'a str, &'a str)>,
    ) -> FnvHashSet<AttrId> {
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

            output.insert(*attr_id);
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
    pub fn put(&mut self, attribute_label: String, attribute_id: AttrId) {
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
    type IntoIter = hash_map::IntoIter<String, AttrId>;
    type Item = (String, AttrId);

    fn into_iter(self) -> Self::IntoIter {
        self.attributes.into_iter()
    }
}

impl<'a> IntoIterator for &'a AttributeMappings {
    type IntoIter = hash_map::Iter<'a, String, AttrId>;
    type Item = (&'a String, &'a AttrId);

    fn into_iter(self) -> Self::IntoIter {
        self.attributes.iter()
    }
}
