//! Authly protobuf types.

/// Tonic types for the `authly_service` protobuf definition.
pub mod service {
    // for some reason the generated code is undocumented.
    // #![allow(missing_docs)]

    tonic::include_proto!("authly_service");
}
