//! Code related to the connection to Authly.

use std::{borrow::Cow, sync::Arc};

use authly_common::{id::ServiceId, proto::service::authly_service_client::AuthlyServiceClient};
use tonic::transport::Endpoint;

use crate::{
    builder::{ConnectionParamsBuilder, Inference},
    error,
    identity::Identity,
    Error,
};

/// The parameters used to establish a connection to Authly.
#[derive(Clone)]
pub struct ConnectionParams {
    pub(crate) inference: Inference,
    pub(crate) url: Cow<'static, str>,
    pub(crate) authly_local_ca: Vec<u8>,
    pub(crate) identity: Identity,
    pub(crate) entity_id: ServiceId,
    pub(crate) jwt_decoding_key: jsonwebtoken::DecodingKey,
}

impl ConnectionParams {
    /// Gets the current Authly root CA.
    pub fn ca_pem(&self) -> &[u8] {
        &self.authly_local_ca
    }

    /// Gets the entity to be used for a connection.
    pub fn identity(&self) -> &Identity {
        &self.identity
    }
}

pub(crate) struct Connection {
    pub authly_service: AuthlyServiceClient<tonic::transport::Channel>,
    pub params: Arc<ConnectionParams>,
}

#[derive(Clone)]
pub(crate) enum ReconfigureStrategy {
    ReInfer { url: Cow<'static, str> },
    Params(Arc<ConnectionParams>),
}

impl ReconfigureStrategy {
    pub(crate) async fn new_connection_params(&self) -> Result<Arc<ConnectionParams>, Error> {
        match self {
            Self::ReInfer { url } => {
                let mut params_builder = ConnectionParamsBuilder::new(url.clone());
                params_builder.infer().await?;
                Ok(params_builder.try_into_connection_params()?)
            }
            Self::Params(params) => Ok(params.clone()),
        }
    }
}

pub(crate) async fn make_connection(params: Arc<ConnectionParams>) -> Result<Connection, Error> {
    let tls_config = tonic::transport::ClientTlsConfig::new()
        .ca_certificate(tonic::transport::Certificate::from_pem(
            &params.authly_local_ca,
        ))
        .identity(tonic::transport::Identity::from_pem(
            params.identity.cert_pem.clone(),
            params.identity.key_pem.clone(),
        ));

    let endpoint = match &params.url {
        Cow::Borrowed(url) => Endpoint::from_static(url),
        Cow::Owned(url) => Endpoint::from_shared(url.clone()).map_err(error::network)?,
    }
    .tls_config(tls_config)
    .map_err(error::network)?;

    let authly_service =
        AuthlyServiceClient::new(endpoint.connect().await.map_err(error::unclassified)?);

    Ok(Connection {
        authly_service,
        params,
    })
}
