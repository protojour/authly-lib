//! Access control functionality.

use std::{future::Future, pin::Pin, sync::Arc};

use authly_common::{
    id::{AttrId, Eid},
    proto::service::{self as proto, authly_service_client::AuthlyServiceClient},
    service::NamespacePropertyMapping,
};
use fnv::FnvHashSet;
use http::header::AUTHORIZATION;
use tonic::{transport::Channel, Request};

use crate::{error, id_codec_error, token::AccessToken, Client, Error};

/// Trait for initiating an access control request
pub trait AccessControl {
    /// Make a new access control request, returning a builder for building it.
    fn access_control_request(&self) -> AccessControlRequestBuilder<'_>;

    /// Evaluate the access control request.
    fn evaluate(
        &self,
        builder: AccessControlRequestBuilder<'_>,
    ) -> Pin<Box<dyn Future<Output = Result<bool, Error>> + Send + '_>>;
}

/// A builder for making an access control request.
///
// TODO: Include peer service(s) in the access control request.
// For that to work locally, there are two options:
// 1. The service verifies each incoming peer with a call to authly, to retrieve entity attributes.
// 2. The service is conscious about its mesh, and is allowed to keep an in-memory map of incoming service entity attributes.
pub struct AccessControlRequestBuilder<'c> {
    access_control: &'c (dyn AccessControl + Send),
    property_mapping: Arc<NamespacePropertyMapping>,
    access_token: Option<Arc<AccessToken>>,
    resource_attributes: FnvHashSet<AttrId>,
    peer_entity_ids: FnvHashSet<Eid>,
}

impl<'c> AccessControlRequestBuilder<'c> {
    /// Create a new builder with the given [AccessControl] backend.
    pub fn new(
        access_control: &'c (dyn AccessControl + Send),
        property_mapping: Arc<NamespacePropertyMapping>,
    ) -> Self {
        Self {
            access_control,
            property_mapping,
            access_token: None,
            resource_attributes: Default::default(),
            peer_entity_ids: Default::default(),
        }
    }

    /// Define a labelled resource attribute to be included in the access control request.
    ///
    /// The property and attribute labels should be available to this service through authly document manifests.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use authly_client::*;
    /// # async fn test() -> anyhow::Result<()> {
    /// // note: Client is not properly built here.
    /// let client = Client::builder().connect().await?;
    ///
    /// client.access_control_request()
    ///     .resource_attribute("my_namespace", "type", "orders")?
    ///     .resource_attribute("my_namespace", "action", "read")?
    ///     .evaluate()
    ///     .await?;
    ///
    /// # Ok(())
    /// # }
    /// ```
    pub fn resource_attribute(
        mut self,
        namespace_label: &str,
        property_label: &str,
        attribute_label: &str,
    ) -> Result<Self, Error> {
        let attr_id = self
            .property_mapping
            .attribute_object_id(namespace_label, property_label, attribute_label)
            .ok_or(Error::InvalidPropertyAttributeLabel)?;

        self.resource_attributes.insert(attr_id);
        Ok(self)
    }

    /// Include an access token in the request.
    ///
    /// The access token is used as subject properties in the access control request.
    pub fn access_token(mut self, token: Arc<AccessToken>) -> Self {
        self.access_token = Some(token);
        self
    }

    /// Add a peer entity ID, which represents a client acting as a subject in the access control request.
    pub fn peer_entity_id(mut self, entity_id: Eid) -> Self {
        self.peer_entity_ids.insert(entity_id);
        self
    }

    /// Get an iterator over the current resource attributes.
    pub fn resource_attributes(&self) -> impl Iterator<Item = AttrId> + use<'_> {
        self.resource_attributes.iter().copied()
    }

    /// Evaluate the access control request.
    ///
    /// The return value represents whether access was granted.
    pub async fn evaluate(self) -> Result<bool, Error> {
        self.access_control.evaluate(self).await
    }
}

pub(crate) async fn get_resource_property_mapping(
    mut service: AuthlyServiceClient<Channel>,
) -> Result<Arc<NamespacePropertyMapping>, Error> {
    let response = service
        .get_resource_property_mappings(proto::Empty::default())
        .await
        .map_err(error::tonic)?;

    let mut property_mapping = NamespacePropertyMapping::default();

    for namespace in response.into_inner().namespaces {
        let ns = property_mapping.namespace_mut(namespace.label);

        for property in namespace.properties {
            let ns_prop = ns.property_mut(property.label);

            for attribute in property.attributes {
                ns_prop.put(
                    attribute.label,
                    AttrId::from_raw_bytes(&attribute.obj_id).ok_or_else(id_codec_error)?,
                );
            }
        }
    }

    Ok(Arc::new(property_mapping))
}

impl AccessControl for Client {
    fn access_control_request(&self) -> AccessControlRequestBuilder<'_> {
        AccessControlRequestBuilder::new(self, self.state.resource_property_mapping.load_full())
    }

    fn evaluate(
        &self,
        builder: AccessControlRequestBuilder<'_>,
    ) -> Pin<Box<dyn Future<Output = Result<bool, Error>> + Send + '_>> {
        Box::pin(async move {
            let mut request = Request::new(proto::AccessControlRequest {
                resource_attributes: builder
                    .resource_attributes
                    .into_iter()
                    .map(|attr| attr.to_raw_array().to_vec())
                    .collect(),
                // Peer entity attributes are currently not known to the service:
                peer_entity_attributes: vec![],
                peer_entity_ids: builder
                    .peer_entity_ids
                    .into_iter()
                    .map(|eid| eid.to_raw_array().to_vec())
                    .collect(),
            });
            if let Some(access_token) = builder.access_token {
                request.metadata_mut().append(
                    AUTHORIZATION.as_str(),
                    format!("Bearer {}", access_token.token)
                        .parse()
                        .map_err(error::unclassified)?,
                );
            }

            let access_control_response = self
                .current_service()
                .access_control(request)
                .await
                .map_err(error::tonic)?
                .into_inner();

            Ok(access_control_response.value > 0)
        })
    }
}
