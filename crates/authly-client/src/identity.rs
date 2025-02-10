//! Client identity, in the TLS sense.

use std::{borrow::Cow, str::FromStr};

use authly_common::id::Eid;
use pem::{EncodeConfig, Pem};

use crate::Error;

/// Client identitity.
///
/// All authly clients identifies themselves using mutual TLS.
#[derive(Clone)]
pub struct Identity {
    pub(crate) cert_pem: Vec<u8>,
    pub(crate) key_pem: Vec<u8>,
}

impl Identity {
    /// Load identity from PEM file containing a certificate and private key.
    pub fn from_pem(pem: impl AsRef<[u8]>) -> Result<Self, Error> {
        use rustls_pemfile::Item;
        use std::io::Cursor;

        let mut pem = Cursor::new(pem);
        let mut certs = Vec::<rustls_pki_types::CertificateDer>::new();
        let mut keys = Vec::<rustls_pki_types::PrivateKeyDer>::new();

        for result in rustls_pemfile::read_all(&mut pem) {
            match result {
                Ok(Item::X509Certificate(cert)) => certs.push(cert),
                Ok(Item::Pkcs1Key(key)) => keys.push(key.into()),
                Ok(Item::Pkcs8Key(key)) => keys.push(key.into()),
                Ok(Item::Sec1Key(key)) => keys.push(key.into()),
                Ok(_) => {
                    return Err(Error::Identity("No valid certificate was found"));
                }
                Err(_) => {
                    return Err(Error::Identity("Invalid identity PEM file"));
                }
            }
        }

        let Some(cert) = certs.into_iter().next() else {
            return Err(Error::Identity("Certificate not found"));
        };
        let Some(key) = keys.into_iter().next() else {
            return Err(Error::Identity("Private key not found"));
        };

        Ok(Self {
            cert_pem: pem::encode_config(
                &Pem::new("CERTIFICATE", cert.to_vec()),
                EncodeConfig::new().set_line_ending(pem::LineEnding::LF),
            )
            .into_bytes(),
            key_pem: pem::encode_config(
                &Pem::new("PRIVATE KEY", key.secret_der()),
                EncodeConfig::new().set_line_ending(pem::LineEnding::LF),
            )
            .into_bytes(),
        })
    }

    /// Get the PEM encoded certificate.
    pub fn cert_pem(&self) -> Cow<[u8]> {
        self.cert_pem.as_slice().into()
    }

    /// Get the PEM encoded private key.
    pub fn key_pem(&self) -> Cow<[u8]> {
        self.key_pem.as_slice().into()
    }

    /// Get a PEM containing both the certificate and the private key.
    pub fn pem(&self) -> Result<Cow<[u8]>, Error> {
        let mut identity_pem = self.cert_pem.clone();
        identity_pem.extend(&self.key_pem);
        Ok(Cow::Owned(identity_pem))
    }
}

#[derive(Clone)]
pub(crate) struct IdentityData {
    pub entity_id: Eid,
}

pub(crate) fn parse_identity_data(cert: &[u8]) -> Result<IdentityData, Error> {
    let pem = pem::parse(cert).map_err(|_| Error::AuthlyCA("invalid authly certificate"))?;

    let (_, x509_cert) = x509_parser::parse_x509_certificate(pem.contents())
        .map_err(|_| Error::AuthlyCA("invalid authly certificate"))?;

    let mut entity_id: Option<Eid> = None;

    for subject_attr in x509_cert.subject().iter_attributes() {
        if let Some(oid_iter) = subject_attr.attr_type().iter() {
            if oid_iter.eq(authly_common::certificate::oid::ENTITY_UNIQUE_IDENTIFIER
                .iter()
                .copied())
            {
                let value = subject_attr
                    .attr_value()
                    .as_str()
                    .map_err(|_| Error::Identity("Entity Id value encoding"))?;
                entity_id = Some(
                    Eid::from_str(value)
                        .map_err(|_| Error::Identity("Entity Id value encoding"))?,
                );
            }
        }
    }

    let entity_id = entity_id.ok_or_else(|| Error::Identity("Entity Id is missing"))?;

    // Assume that EC is always used
    Ok(IdentityData { entity_id })
}
