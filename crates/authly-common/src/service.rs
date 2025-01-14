//! Authly service utilities and helpers

use std::collections::HashMap;

use fnv::FnvHashSet;

use crate::id::ObjId;

/// A property mapping maps human-readable property and attribute labels to [ObjId]s.
#[derive(Default)]
pub struct PropertyMapping {
    properties: HashMap<String, AttributeMappings>,
}

#[derive(Default)]
struct AttributeMappings {
    attributes: HashMap<String, ObjId>,
}

impl PropertyMapping {
    /// Add an property/attribute/attribute-id triple to the mapping.
    pub fn add(&mut self, property_label: String, attribute_label: String, attribute_id: ObjId) {
        self.properties
            .entry(property_label)
            .or_default()
            .attributes
            .insert(attribute_label, attribute_id);
    }

    /// Get the object ID of a single property/attribute label pair, if found.
    pub fn attribute_object_id(
        &self,
        property_label: &str,
        attribute_label: &str,
    ) -> Option<ObjId> {
        let attribute_mapping = self.properties.get(property_label)?;
        attribute_mapping.attributes.get(attribute_label).cloned()
    }

    /// Translate the given property/attribute labels to underlying [ObjId]s.
    pub fn translate<'a>(
        &self,
        attributes: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> FnvHashSet<u128> {
        let mut output = FnvHashSet::default();
        for (prop, attr) in attributes {
            let Some(attr_mappings) = self.properties.get(prop) else {
                continue;
            };
            let Some(attr_id) = attr_mappings.attributes.get(attr) else {
                continue;
            };

            output.insert(attr_id.value());
        }

        output
    }
}
