/// Errors that can happen either during client configuration or while communicating over the network.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// Error generating a private key.
    #[error("private key gen error")]
    PrivateKeyGen,

    /// A problem with the Authly Certificate Authority.
    #[error("Authly CA error: {0}")]
    AuthlyCA(&'static str),

    /// A problem with the client identity.
    #[error("identity error: {0}")]
    Identity(&'static str),

    /// Automatic environment inference did not work.
    #[error("environment not inferrable")]
    EnvironmentNotInferrable,

    /// A party was not authenticated or an operation was forbidden.
    #[error("unauthorized: {0}")]
    Unauthorized(anyhow::Error),

    /// A network problem.
    #[error("network error: {0}")]
    Network(anyhow::Error),

    /// An access token problem.
    #[error("invalid access token: {0}")]
    InvalidAccessToken(anyhow::Error),

    /// A codec problem, usually related to network protocols.
    #[error("encoding error: {0}")]
    Codec(anyhow::Error),

    /// Invalid property/attribute label
    #[error("invalid property/attribute label")]
    InvalidPropertyAttributeLabel,

    /// Other type of unclassified error.
    #[error("unclassified error: {0}")]
    Unclassified(anyhow::Error),
}

pub(crate) fn unclassified(err: impl std::error::Error + Send + Sync + 'static) -> Error {
    Error::Unclassified(anyhow::Error::from(err))
}

pub(crate) fn tonic(err: tonic::Status) -> Error {
    match err.code() {
        tonic::Code::Unauthenticated => Error::Unauthorized(err.into()),
        tonic::Code::PermissionDenied => Error::Unauthorized(err.into()),
        _ => Error::Network(err.into()),
    }
}

pub(crate) fn network(err: impl std::error::Error + Send + Sync + 'static) -> Error {
    Error::Unauthorized(anyhow::Error::from(err))
}

pub(crate) fn unauthorized(err: impl std::error::Error + Send + Sync + 'static) -> Error {
    Error::Unauthorized(anyhow::Error::from(err))
}
