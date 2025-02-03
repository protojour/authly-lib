//! `authly-client` is an asynchronous Rust client handle for services interfacing with the authly service.
//!
//! At present, it only works with the `tokio` runtime.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub use authly_common::service::NamespacePropertyMapping;
pub use builder::ClientBuilder;
use builder::ConnectionParamsBuilder;
use connection::{Connection, ConnectionParams, ReconfigureStrategy};
pub use error::Error;
use metadata::{NamespaceMetadata, ServiceMetadata};
use rcgen::{CertificateParams, DnType, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
pub use token::AccessToken;

use access_control::AccessControlRequestBuilder;
use arc_swap::ArcSwap;

use std::{borrow::Cow, sync::Arc};

use anyhow::anyhow;
use authly_common::{
    access_token::AuthlyAccessTokenClaims,
    id::Eid,
    proto::{
        proto_struct_to_json,
        service::{self as proto, authly_service_client::AuthlyServiceClient},
    },
};
use http::header::COOKIE;
use tonic::{transport::Channel, Request};

pub mod access_control;
pub mod identity;
pub mod metadata;
pub mod token;

mod background_worker;
mod builder;
mod connection;
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
    state: Arc<ClientState>,
}

/// Shared data for cloned clients
struct ClientState {
    /// The current connection
    conn: ArcSwap<Connection>,

    /// How to reconfigure the connection
    reconfigure: ReconfigureStrategy,

    /// Triggered when the client gets reconfigured
    #[allow(unused)]
    reconfigured_rx: tokio::sync::watch::Receiver<Arc<ConnectionParams>>,

    /// signal sent when the state is dropped
    closed_tx: tokio::sync::watch::Sender<()>,

    /// The resource property mapping for this service.
    /// It's kept in an ArcSwap to potentially support live-update of this structure.
    /// For that to work, the client should keep a subscription option and listen
    /// for change events and re-download the property mapping.
    resource_property_mapping: ArcSwap<NamespacePropertyMapping>,
}

impl Drop for ClientState {
    fn drop(&mut self) {
        let _ = self.closed_tx.send(());
    }
}

impl Client {
    /// Construct a new builder.
    pub fn builder() -> ClientBuilder {
        let url = std::env::var("AUTHLY_URL")
            .map(Cow::Owned)
            .unwrap_or(Cow::Borrowed("https://authly"));

        ClientBuilder {
            inner: ConnectionParamsBuilder::new(url),
        }
    }

    /// Retrieve the [ServiceMetadata] about service this client identifies as.
    pub async fn metadata(&self) -> Result<ServiceMetadata, Error> {
        let proto = self
            .current_service()
            .get_metadata(proto::Empty::default())
            .await
            .map_err(error::tonic)?
            .into_inner();

        Ok(ServiceMetadata {
            entity_id: Eid::from_raw_bytes(&proto.entity_id).ok_or_else(id_codec_error)?,
            label: proto.label,
            namespaces: proto
                .namespaces
                .into_iter()
                .map(|proto| NamespaceMetadata {
                    label: proto.label,
                    metadata: proto.metadata.map(proto_struct_to_json),
                })
                .collect(),
        })
    }

    /// Make a new access control request, returning a builder for building it.
    pub fn access_control_request(&self) -> AccessControlRequestBuilder<'_> {
        AccessControlRequestBuilder::new(self)
    }

    /// Get the current resource properties of this service, in the form of a [PropertyMapping].
    pub fn get_resource_property_mapping(&self) -> Arc<NamespacePropertyMapping> {
        self.state.resource_property_mapping.load_full()
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
            &self.state.conn.load().params.jwt_decoding_key,
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
        let mut request = Request::new(proto::Empty::default());

        // TODO: This should use Authorization instead of Cookie?
        request.metadata_mut().append(
            COOKIE.as_str(),
            format!("session-cookie={session_token}")
                .parse()
                .map_err(error::unclassified)?,
        );

        let proto = self
            .current_service()
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
            .state
            .conn
            .load()
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

    /// Return a stream of [rustls::ServerConfig] values for configuring authly-verified servers.
    /// The first stream item will resolve immediately.
    ///
    /// The config comes with `h2` and `http/1.1` ALPN protocols.
    /// This may become configurable in the future.
    ///
    /// For now, this only renews the server certificate when absolutely required.
    /// In the future, this may rotate server certificates automatically on a fixed (configurable) interval.
    #[cfg(feature = "rustls_023")]
    pub async fn rustls_server_configurer(
        &self,
        common_name: impl Into<Cow<'static, str>>,
    ) -> Result<futures_util::stream::BoxStream<'static, Arc<rustls::ServerConfig>>, Error> {
        use std::time::Duration;

        use futures_util::StreamExt;
        use rustls::{server::WebPkiClientVerifier, RootCertStore};
        use rustls_pki_types::pem::PemObject;

        async fn rebuild_server_config(
            client: Client,
            params: Arc<ConnectionParams>,
            common_name: Cow<'static, str>,
        ) -> Result<Arc<rustls::ServerConfig>, Error> {
            let mut root_cert_store = RootCertStore::empty();
            root_cert_store
                .add(
                    CertificateDer::from_pem_slice(&params.authly_local_ca)
                        .map_err(|_err| Error::AuthlyCA("unable to parse"))?,
                )
                .map_err(|_err| Error::AuthlyCA("unable to include in root cert store"))?;

            let (cert, key) = client.generate_server_tls_params(&common_name).await?;

            let mut tls_config = rustls::server::ServerConfig::builder()
                .with_client_cert_verifier(
                    WebPkiClientVerifier::builder(root_cert_store.into())
                        .build()
                        .map_err(|_| Error::AuthlyCA("cannot build a WebPki client verifier"))?,
                )
                .with_single_cert(vec![cert], key)
                .map_err(|_| Error::Tls("Unable to configure server"))?;
            tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

            Ok(Arc::new(tls_config))
        }

        let client = self.clone();
        let common_name = common_name.into();
        let mut reconfigured_rx = self.state.reconfigured_rx.clone();
        let initial_params = reconfigured_rx.borrow_and_update().clone();
        let initial_tls_config =
            rebuild_server_config(client.clone(), initial_params, common_name.clone()).await?;

        let immediate_stream = futures_util::stream::iter([initial_tls_config]);

        let rotation_stream =
            futures_util::stream::unfold(reconfigured_rx, move |mut reconfigured_rx| {
                let client = client.clone();
                let common_name = common_name.clone();

                async move {
                    // wait for configuration change
                    let Ok(()) = reconfigured_rx.changed().await else {
                        // client dropped
                        return None;
                    };

                    loop {
                        let params = reconfigured_rx.borrow_and_update().clone();
                        let server_config_result =
                            rebuild_server_config(client.clone(), params, common_name.clone())
                                .await;

                        match server_config_result {
                            Ok(server_config) => return Some((server_config, reconfigured_rx)),
                            Err(err) => {
                                tracing::error!(
                                    ?err,
                                    "could not regenerate TLS server config, trying again soon"
                                );
                                tokio::time::sleep(Duration::from_secs(10)).await;
                            }
                        }
                    }
                }
            });

        Ok(immediate_stream.chain(rotation_stream).boxed())
    }

    /// Generates a stream of [reqwest::ClientBuilder] preconfigured with Authly TLS paramaters.
    /// The first stream item will resolve immediately.
    #[cfg(feature = "reqwest_012")]
    pub async fn request_client_builder_stream(
        &self,
    ) -> Result<futures_util::stream::BoxStream<'static, reqwest::ClientBuilder>, Error> {
        use std::time::Duration;

        use futures_util::StreamExt;

        fn rebuild(params: Arc<ConnectionParams>) -> Result<reqwest::ClientBuilder, Error> {
            Ok(reqwest::Client::builder()
                .add_root_certificate(
                    reqwest::tls::Certificate::from_pem(&params.authly_local_ca)
                        .map_err(|_| Error::AuthlyCA("unable to parse"))?,
                )
                .identity(
                    reqwest::Identity::from_pem(params.identity.to_pem()?.as_ref())
                        .map_err(|_| Error::Identity("unable to parse"))?,
                ))
        }

        let mut reconfigured_rx = self.state.reconfigured_rx.clone();
        let initial_params = reconfigured_rx.borrow_and_update().clone();

        let initial_builder = rebuild(initial_params)?;
        let immediate_stream = futures_util::stream::iter([initial_builder]);

        let rotation_stream =
            futures_util::stream::unfold(reconfigured_rx, move |mut reconfigured_rx| {
                async move {
                    // wait for configuration change
                    let Ok(()) = reconfigured_rx.changed().await else {
                        // client dropped
                        return None;
                    };

                    loop {
                        let params = reconfigured_rx.borrow_and_update().clone();

                        match rebuild(params) {
                            Ok(server_config) => return Some((server_config, reconfigured_rx)),
                            Err(err) => {
                                tracing::error!(
                                    ?err,
                                    "could not regenerate reqwest ClientBuilder, retrying soon"
                                );
                                tokio::time::sleep(Duration::from_secs(10)).await;
                            }
                        }
                    }
                }
            });

        Ok(immediate_stream.chain(rotation_stream).boxed())
    }
}

/// Private methods
impl Client {
    fn current_service(&self) -> AuthlyServiceClient<Channel> {
        self.state.conn.load().authly_service.clone()
    }
}

fn id_codec_error() -> Error {
    Error::Codec(anyhow!("id decocing error"))
}
