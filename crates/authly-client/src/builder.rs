use std::{borrow::Cow, sync::Arc};

use arc_swap::ArcSwap;
use authly_common::proto::service::authly_service_client::AuthlyServiceClient;
use http::header::AUTHORIZATION;
use pem::{EncodeConfig, Pem};
use rcgen::KeyPair;

use crate::{
    access_control, error, identity::Identity, Client, ClientInner, Error, IDENTITY_PATH,
    K8S_SA_TOKENFILE_PATH, LOCAL_CA_CERT_PATH,
};

/// A builder for configuring a [Client].
pub struct ClientBuilder {
    pub(crate) authly_local_ca: Option<Vec<u8>>,
    pub(crate) identity: Option<Identity>,
    pub(crate) jwt_decoding_key: Option<jsonwebtoken::DecodingKey>,
    pub(crate) url: Cow<'static, str>,
}

impl ClientBuilder {
    /// Infer the Authly client from the environment it runs in.
    pub async fn from_environment(mut self) -> Result<Self, Error> {
        let authly_local_ca =
            std::fs::read(LOCAL_CA_CERT_PATH).map_err(|_| Error::AuthlyCA("not mounted"))?;
        self.jwt_decoding_key = Some(jwt_decoding_key_from_cert(&authly_local_ca)?);

        if std::fs::exists(IDENTITY_PATH).unwrap_or(false) {
            self.authly_local_ca = Some(authly_local_ca);
            self.identity = Some(
                Identity::from_pem(std::fs::read(IDENTITY_PATH).unwrap())
                    .map_err(|_| Error::Identity("invalid identity"))?,
            );

            Ok(self)
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
                .post("https://authly-k8s/api/csr")
                .body(key_pair.public_key_der())
                .header(AUTHORIZATION, format!("Bearer {token}"))
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

            Ok(self)
        } else {
            Err(Error::EnvironmentNotInferrable)
        }
    }

    /// Use the given CA certificate to verify the Authly server
    pub fn with_authly_local_ca_pem(mut self, ca: Vec<u8>) -> Result<Self, Error> {
        self.jwt_decoding_key = Some(jwt_decoding_key_from_cert(&ca)?);
        self.authly_local_ca = Some(ca);
        Ok(self)
    }

    /// Use a pre-certified client identity
    pub fn with_identity(mut self, identity: Identity) -> Self {
        self.identity = Some(identity);
        self
    }

    /// Override Authly URL (default is https://authly)
    pub fn with_url(mut self, url: impl Into<String>) -> Self {
        self.url = url.into().into();
        self
    }

    /// Get the current Authly local CA of the builder as a PEM-encoded byte buffer.
    pub fn get_local_ca_pem(&self) -> Result<Cow<[u8]>, Error> {
        self.authly_local_ca
            .as_ref()
            .map(|ca| Cow::Borrowed(ca.as_slice()))
            .ok_or_else(|| Error::AuthlyCA("not provideded"))
    }

    /// Get the current Authly identity of the builder as a PEM-encoded byte buffer.
    pub fn get_identity_pem(&self) -> Result<Cow<[u8]>, Error> {
        let identity = self
            .identity
            .as_ref()
            .ok_or_else(|| Error::Identity("not provided"))?;

        let mut identity_pem = identity.cert_pem.clone();
        identity_pem.extend(&identity.key_pem);
        Ok(Cow::Owned(identity_pem))
    }

    /// Connect to Authly
    pub async fn connect(self) -> Result<Client, Error> {
        let authly_local_ca = self
            .authly_local_ca
            .ok_or_else(|| Error::AuthlyCA("not provided"))?;
        let jwt_decoding_key = self
            .jwt_decoding_key
            .ok_or_else(|| Error::AuthlyCA("missing public key"))?;
        let identity = self
            .identity
            .ok_or_else(|| Error::Identity("not provided"))?;

        let tls_config = tonic::transport::ClientTlsConfig::new()
            .ca_certificate(tonic::transport::Certificate::from_pem(&authly_local_ca))
            .identity(tonic::transport::Identity::from_pem(
                identity.cert_pem,
                identity.key_pem,
            ));

        let endpoint = tonic::transport::Endpoint::from_shared(self.url.to_string())
            .map_err(error::network)?
            .tls_config(tls_config)
            .map_err(error::network)?;

        let service =
            AuthlyServiceClient::new(endpoint.connect().await.map_err(error::unclassified)?);

        let resource_property_mapping =
            access_control::get_resource_property_mapping(service.clone()).await?;

        Ok(Client {
            inner: Arc::new(ClientInner {
                service,
                jwt_decoding_key,
                resource_property_mapping: Arc::new(ArcSwap::new(resource_property_mapping)),
            }),
        })
    }
}

fn jwt_decoding_key_from_cert(cert: &[u8]) -> Result<jsonwebtoken::DecodingKey, Error> {
    let pem = pem::parse(cert).map_err(|_| Error::AuthlyCA("invalid authly certificate"))?;

    let (_, x509_cert) = x509_parser::parse_x509_certificate(pem.contents())
        .map_err(|_| Error::AuthlyCA("invalid authly certificate"))?;

    let public_key = x509_cert.public_key();

    // Assume that EC is always used
    Ok(jsonwebtoken::DecodingKey::from_ec_der(
        &public_key.subject_public_key.data,
    ))
}
