//! Client service metadata.

use authly_common::id::Eid;

/// A structure which provides various pieces of information about the service.
///
/// Metadata is not required for the service to function, but can be used optionally to
/// convey application-specific data from the Authly database to the service.
pub struct ServiceMetadata {
    pub(crate) entity_id: Eid,

    pub(crate) label: String,

    pub(crate) namespaces: Vec<NamespaceMetadata>,
}

impl ServiceMetadata {
    /// Get the entity ID ([Eid]) of the Authly service this client identifies as.
    pub fn entity_id(&self) -> Eid {
        self.entity_id
    }

    /// Get the label the service was given when registered in Authly.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Get the list of namespace metadata for the namespaces this service has access to.
    ///
    /// The list comes in no particular order and should be interpreted as a set.
    pub fn namespaces(&self) -> &[NamespaceMetadata] {
        &self.namespaces
    }
}

/// Metadata about a namespace the service has access to.
pub struct NamespaceMetadata {
    pub(crate) label: String,
    pub(crate) metadata: Option<serde_json::Map<String, serde_json::Value>>,
}

impl NamespaceMetadata {
    /// The label of this namespace as configured in Authly.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Application-specific metadata of this namespace, encoded as a JSON map.
    pub fn metadata(&self) -> Option<&serde_json::Map<String, serde_json::Value>> {
        self.metadata.as_ref()
    }

    /// Application-specific metadata, owned version.
    pub fn into_metadata(self) -> Option<serde_json::Map<String, serde_json::Value>> {
        self.metadata
    }
}
