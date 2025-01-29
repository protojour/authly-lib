use std::{borrow::Cow, sync::Arc};

use arc_swap::ArcSwap;
use http::header::AUTHORIZATION;
use pem::{EncodeConfig, Pem};
use rcgen::KeyPair;

use crate::{
    access_control,
    background_worker::spawn_background_worker,
    connection::{make_connection, ConnectionParams, ReconfigureStrategy},
    error,
    identity::Identity,
    Client, ClientState, Error, IDENTITY_PATH, K8S_SA_TOKENFILE_PATH, LOCAL_CA_CERT_PATH,
};

#[derive(Clone, Copy)]
pub(crate) enum Inference {
    Inferred,
    Manual,
}

/// A builder for configuring a [Client].
pub struct ClientBuilder {
    pub(crate) inner: ConnectionParamsBuilder,
}

impl ClientBuilder {
    /// Infer the Authly client from the environment it runs in.
    pub async fn from_environment(mut self) -> Result<Self, Error> {
        self.inner.infer().await?;
        Ok(self)
    }

    /// Use the given CA certificate to verify the Authly server
    pub fn with_authly_local_ca_pem(mut self, ca: Vec<u8>) -> Result<Self, Error> {
        self.inner.inference = Inference::Manual;
        self.inner.jwt_decoding_key = Some(jwt_decoding_key_from_cert(&ca)?);
        self.inner.authly_local_ca = Some(ca);
        Ok(self)
    }

    /// Use a pre-certified client identity
    pub fn with_identity(mut self, identity: Identity) -> Self {
        self.inner.inference = Inference::Manual;
        self.inner.identity = Some(identity);
        self
    }

    /// Override Authly URL (default is https://authly)
    pub fn with_url(mut self, url: impl Into<String>) -> Self {
        self.inner.url = url.into().into();
        self
    }

    /// Get the current Authly local CA of the builder as a PEM-encoded byte buffer.
    pub fn get_local_ca_pem(&self) -> Result<Cow<[u8]>, Error> {
        self.inner
            .authly_local_ca
            .as_ref()
            .map(|ca| Cow::Borrowed(ca.as_slice()))
            .ok_or_else(|| Error::AuthlyCA("unconfigured"))
    }

    /// Get the current Authly identity of the builder as a PEM-encoded byte buffer.
    pub fn get_identity_pem(&self) -> Result<Cow<[u8]>, Error> {
        let identity = self
            .inner
            .identity
            .as_ref()
            .ok_or_else(|| Error::Identity("unconfigured"))?;

        let mut identity_pem = identity.cert_pem.clone();
        identity_pem.extend(&identity.key_pem);
        Ok(Cow::Owned(identity_pem))
    }

    /// Connect to Authly
    pub async fn connect(self) -> Result<Client, Error> {
        let params = self.inner.try_into_connection_params()?;
        let connection = make_connection(params.clone()).await?;
        let (reconfigured_tx, reconfigured_rx) = tokio::sync::watch::channel(params.clone());

        let reconfigure = match params.inference {
            Inference::Inferred => ReconfigureStrategy::ReInfer {
                url: params.url.clone(),
            },
            Inference::Manual => ReconfigureStrategy::Params(params),
        };

        let resource_property_mapping =
            access_control::get_resource_property_mapping(connection.authly_service.clone())
                .await?;

        let (closed_tx, closed_rx) = tokio::sync::watch::channel(());
        let state = Arc::new(ClientState {
            conn: ArcSwap::new(Arc::new(connection)),
            reconfigure,
            reconfigured_rx,
            closed_tx,
            resource_property_mapping: ArcSwap::new(resource_property_mapping),
        });

        spawn_background_worker(state.clone(), reconfigured_tx, closed_rx).await?;

        let client = Client { state };

        Ok(client)
    }
}

#[derive(Clone)]
pub(crate) struct ConnectionParamsBuilder {
    pub inference: Inference,
    pub url: Cow<'static, str>,
    pub authly_local_ca: Option<Vec<u8>>,
    pub identity: Option<Identity>,
    pub jwt_decoding_key: Option<jsonwebtoken::DecodingKey>,
}

impl ConnectionParamsBuilder {
    pub(crate) fn new(url: Cow<'static, str>) -> Self {
        Self {
            inference: Inference::Manual,
            url,
            authly_local_ca: None,
            identity: None,
            jwt_decoding_key: None,
        }
    }

    /// Try to infer the parameters from the environment
    pub(crate) async fn infer(&mut self) -> Result<(), Error> {
        self.inference = Inference::Inferred;
        let authly_local_ca =
            std::fs::read(LOCAL_CA_CERT_PATH).map_err(|_| Error::AuthlyCAmissingInEtc)?;
        self.jwt_decoding_key = Some(jwt_decoding_key_from_cert(&authly_local_ca)?);

        if std::fs::exists(IDENTITY_PATH).unwrap_or(false) {
            self.authly_local_ca = Some(authly_local_ca);
            self.identity = Some(
                Identity::from_pem(std::fs::read(IDENTITY_PATH).unwrap())
                    .map_err(|_| Error::Identity("invalid identity"))?,
            );

            Ok(())
        } else if std::fs::exists(K8S_SA_TOKENFILE_PATH).unwrap_or(false) {
            let key_pair = KeyPair::generate().map_err(|_err| Error::PrivateKeyGen)?;
            let token =
                std::fs::read_to_string(K8S_SA_TOKENFILE_PATH).map_err(error::unclassified)?;

            let client_cert = reqwest::ClientBuilder::new()
                .add_root_certificate(
                    reqwest::Certificate::from_pem(&authly_local_ca)
                        .map_err(error::unclassified)?,
                )
                .build()
                .map_err(error::unclassified)?
                .post("https://authly-k8s/api/v0/authenticate")
                .header(AUTHORIZATION, format!("Bearer {token}"))
                .body(key_pair.public_key_der())
                .send()
                .await
                .map_err(error::unauthorized)?
                .error_for_status()
                .map_err(error::unauthorized)?
                .bytes()
                .await
                .map_err(error::unclassified)?;
            let client_cert_pem = pem::encode_config(
                &Pem::new("CERTIFICATE", client_cert),
                EncodeConfig::new().set_line_ending(pem::LineEnding::LF),
            );

            self.authly_local_ca = Some(authly_local_ca);
            self.identity = Some(Identity {
                cert_pem: client_cert_pem.into_bytes(),
                key_pem: key_pair.serialize_pem().into_bytes(),
            });

            Ok(())
        } else {
            Err(Error::EnvironmentNotInferrable)
        }
    }

    pub fn try_into_connection_params(self) -> Result<Arc<ConnectionParams>, Error> {
        let authly_local_ca = self
            .authly_local_ca
            .clone()
            .ok_or_else(|| Error::AuthlyCA("unconfigured"))?;
        let jwt_decoding_key = self
            .jwt_decoding_key
            .ok_or_else(|| Error::AuthlyCA("public key not found"))?;
        let identity = self
            .identity
            .ok_or_else(|| Error::Identity("unconfigured"))?;

        Ok(Arc::new(ConnectionParams {
            inference: self.inference,
            url: self.url,
            authly_local_ca,
            jwt_decoding_key,
            identity,
        }))
    }
}

pub fn jwt_decoding_key_from_cert(cert: &[u8]) -> Result<jsonwebtoken::DecodingKey, Error> {
    let pem = pem::parse(cert).map_err(|_| Error::AuthlyCA("invalid authly certificate"))?;

    let (_, x509_cert) = x509_parser::parse_x509_certificate(pem.contents())
        .map_err(|_| Error::AuthlyCA("invalid authly certificate"))?;

    let public_key = x509_cert.public_key();

    // Assume that EC is always used
    Ok(jsonwebtoken::DecodingKey::from_ec_der(
        &public_key.subject_public_key.data,
    ))
}
