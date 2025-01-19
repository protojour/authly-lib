//! Utilities for creating mTLS servers participating in an Authly service mesh.

use http::Request;
use hyper::body::Incoming;
use tracing::warn;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::id::Eid;

/// A [Request] extension representing the peer Authly service that connected to the local server.
#[derive(Clone, Copy, Debug)]
pub struct PeerServiceEntity(pub Eid);

/// A middleware for setting up mTLS with [tower_server].
#[derive(Clone)]
pub struct MTLSMiddleware;

/// The
#[derive(Default)]
pub struct MTLSConnectionData {
    peer_service_entity: Option<Eid>,
}

impl tower_server::tls::TlsConnectionMiddleware for MTLSMiddleware {
    type Data = Option<MTLSConnectionData>;

    fn data(&self, connection: &rustls::ServerConnection) -> Self::Data {
        let peer_der = connection.peer_certificates()?.first()?;
        let (_, peer_cert) = X509Certificate::from_der(peer_der).ok()?;

        let mut data = MTLSConnectionData::default();

        for rdn in peer_cert.subject.iter() {
            for attr in rdn.iter() {
                if attr.attr_type() == &x509_parser::oid_registry::OID_X509_COMMON_NAME {
                    if let Ok(common_name) = attr.attr_value().as_str() {
                        if let Ok(entity_id) = common_name.parse() {
                            data.peer_service_entity = Some(entity_id);
                        } else {
                            warn!("failed to parse common name: `{common_name}`");
                        }
                    }
                }
            }
        }

        Some(data)
    }

    fn call(&self, req: &mut Request<Incoming>, data: &Self::Data) {
        let Some(data) = data else {
            return;
        };
        if let Some(id) = data.peer_service_entity {
            req.extensions_mut().insert(PeerServiceEntity(id));
        }
    }
}
