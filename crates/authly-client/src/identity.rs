use pem::{EncodeConfig, Pem};

use crate::Error;

/// Client identitity.
///
/// All authly clients identifies themselves using mutual TLS.
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
}
