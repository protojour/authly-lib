//! `authly-client` is an asynchronous Rust client handle for services interfacing with the authly service.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub use authly_common::service::PropertyMapping;
pub use builder::ClientBuilder;
pub use error::Error;
use rcgen::{CertificateParams, DnType, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
pub use token::AccessToken;

use access_control::AccessControlRequestBuilder;
use arc_swap::ArcSwap;

use std::sync::Arc;

use anyhow::anyhow;
use authly_common::{
    access_token::AuthlyAccessTokenClaims,
    id::Eid,
    proto::service::{self as proto, authly_service_client::AuthlyServiceClient},
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

/// File path for the root CA certificate.
#[expect(unused)]
const ROOT_CA_CERT_PATH: &str = "/etc/authly/certs/root.crt";

/// File path for the local CA certificate.
const LOCAL_CA_CERT_PATH: &str = "/etc/authly/certs/local.crt";

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
    authly_service: AuthlyServiceClient<tonic::transport::Channel>,
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
        let mut service = self.inner.authly_service.clone();
        let metadata = service
            .get_metadata(proto::Empty::default())
            .await
            .map_err(error::tonic)?
            .into_inner();

        Eid::from_bytes(&metadata.entity_id).ok_or_else(id_codec_error)
    }

    /// The name of this client.
    pub async fn label(&self) -> Result<String, Error> {
        let mut service = self.inner.authly_service.clone();
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

    /// Get the current resource properties of this service, in the form of a [PropertyMapping].
    pub fn get_resource_property_mapping(&self) -> Arc<PropertyMapping> {
        self.inner.resource_property_mapping.load_full()
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
        let mut service = self.inner.authly_service.clone();
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

    /// Generate a server certificate and a key pair for the service.
    ///
    /// This involves sending a Certificate Signing Request for Authly to resolve.
    ///
    /// Returns a pair of Certificate signed by the Authly Local CA, and the matching private key to be used by the server.
    pub async fn generate_server_tls_params(
        &self,
        common_name: &str,
    ) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), Error> {
        let params = {
            let mut params = CertificateParams::new(vec![common_name.to_string()])
                .map_err(|_| Error::InvalidCommonName)?;
            params
                .distinguished_name
                .push(DnType::CommonName, common_name);
            params.use_authority_key_identifier_extension = false;
            params.key_usages.push(KeyUsagePurpose::DigitalSignature);
            params
                .extended_key_usages
                .push(ExtendedKeyUsagePurpose::ServerAuth);

            let now = time::OffsetDateTime::now_utc();
            params.not_before = now;

            // A default timeout that is one year.
            // FIXME(rotation) What happens to the server after the certificate expires?
            // No other services would then be able to connect to it, but it wouldn't itself understand that it's broken.
            params.not_after = now.checked_add(time::Duration::days(365)).unwrap();
            params
        };

        // The key pair to use for the server, and signing the Certificate Signing Request.
        // The private key is not sent to Authly.
        let key_pair = KeyPair::generate().map_err(|_err| Error::PrivateKeyGen)?;
        let csr_der = params
            .serialize_request(&key_pair)
            .expect("the parameters should be correct")
            .der()
            .to_vec();

        let proto = self
            .inner
            .authly_service
            .clone()
            .sign_certificate(Request::new(proto::CertificateSigningRequest {
                der: csr_der,
            }))
            .await
            .map_err(error::tonic)?;

        let certificate = CertificateDer::from(proto.into_inner().der);
        let private_key = PrivateKeyDer::try_from(key_pair.serialize_der()).map_err(|err| {
            Error::Unclassified(anyhow!("could not serialize private key: {err}"))
        })?;

        Ok((certificate, private_key))
    }
}

fn id_codec_error() -> Error {
    Error::Codec(anyhow!("id decocing error"))
}
