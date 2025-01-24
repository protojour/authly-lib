//! Authly protobuf types.

/// Tonic types for the `authly_connect` protobuf definition.
pub mod connect {
    tonic::include_proto!("authly_connect");
}

/// Tonic types for the `authly_service` protobuf definition.
pub mod service {
    tonic::include_proto!("authly_service");
}
