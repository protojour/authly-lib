//! `authly-client` is an asynchronous Rust client handle for services interfacing with the authly service.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub use builder::ClientBuilder;
pub use error::Error;
pub use token::AccessToken;

use access_control::AccessControlRequestBuilder;
use arc_swap::ArcSwap;

use std::sync::Arc;

use anyhow::anyhow;
use authly_common::{
    access_token::AuthlyAccessTokenClaims,
    id::Eid,
    proto::service::{self as proto, authly_service_client::AuthlyServiceClient},
    service::PropertyMapping,
};
use http::header::COOKIE;
use tonic::Request;

/// Client identity.
pub mod identity;

/// Token utilities.
pub mod token;

pub mod access_control;

mod builder;
mod error;

/// File path for the local CA certificate.
const LOCAL_CA_CERT_PATH: &str = "/etc/authly/local/ca.crt";

/// File path for the local CA certificate.
const IDENTITY_PATH: &str = "/etc/authly/identity/identity.pem";

/// File path for detecting a valid kubernetes environment.
const K8S_SA_TOKENFILE_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";

/// The authly client handle.
#[derive(Clone)]
pub struct Client {
    inner: Arc<ClientInner>,
}

/// Shared data for cloned clients
struct ClientInner {
    service: AuthlyServiceClient<tonic::transport::Channel>,
    jwt_decoding_key: jsonwebtoken::DecodingKey,

    /// The resource property mapping for this service.
    /// It's kept in an ArcSwap to potentially support live-update of this structure.
    /// For that to work, the client should keep a subscription option and listen
    /// for change events and re-download the property mapping.
    resource_property_mapping: Arc<ArcSwap<PropertyMapping>>,
}

impl Client {
    /// Construct a new builder.
    pub fn builder() -> ClientBuilder {
        let url = std::env::var("AUTHLY_URL").unwrap_or("https://authly".to_string());

        ClientBuilder {
            authly_local_ca: None,
            identity: None,
            jwt_decoding_key: None,
            url: url.into(),
        }
    }

    /// The eid of this client.
    pub async fn entity_id(&self) -> Result<Eid, Error> {
        let mut service = self.inner.service.clone();
        let metadata = service
            .get_metadata(proto::Empty::default())
            .await
            .map_err(error::tonic)?
            .into_inner();

        Eid::from_bytes(&metadata.entity_id).ok_or_else(id_codec_error)
    }

    /// The name of this client.
    pub async fn label(&self) -> Result<String, Error> {
        let mut service = self.inner.service.clone();
        let metadata = service
            .get_metadata(proto::Empty::default())
            .await
            .map_err(error::tonic)?
            .into_inner();

        Ok(metadata.label)
    }

    /// Make a new access control request, returning a builder for building it.
    pub fn access_control_request(&self) -> AccessControlRequestBuilder<'_> {
        AccessControlRequestBuilder::new(self)
    }

    /// Decode and validate an Authly [AccessToken].
    /// The access token usually represents an entity which is a user of the system.
    pub fn decode_access_token(
        &self,
        access_token: impl Into<String>,
    ) -> Result<Arc<AccessToken>, Error> {
        let access_token = access_token.into();
        let validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
        let token_data = jsonwebtoken::decode::<AuthlyAccessTokenClaims>(
            &access_token,
            &self.inner.jwt_decoding_key,
            &validation,
        )
        .map_err(|err| Error::InvalidAccessToken(err.into()))?;

        Ok(Arc::new(AccessToken {
            token: access_token,
            claims: token_data.claims,
        }))
    }

    /// Exchange a session token for an access token suitable for evaluating access control.
    pub async fn get_access_token(&self, session_token: &str) -> Result<Arc<AccessToken>, Error> {
        let mut service = self.inner.service.clone();
        let mut request = Request::new(proto::Empty::default());

        // TODO: This should use Authorization instead of Cookie?
        request.metadata_mut().append(
            COOKIE.as_str(),
            format!("session-cookie={session_token}")
                .parse()
                .map_err(error::unclassified)?,
        );

        let proto = service
            .get_access_token(request)
            .await
            .map_err(error::tonic)?
            .into_inner();

        self.decode_access_token(proto.token)
    }
}

fn id_codec_error() -> Error {
    Error::Codec(anyhow!("id decocing error"))
}
