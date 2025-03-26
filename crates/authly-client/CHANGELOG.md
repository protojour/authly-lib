# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

## [0.0.9] - 2025-03-26
### Changed
- Breaking: Upgrade tonic to 0.13

## [0.0.8] - 2025-02-14
### Changed
- Server certificate alt names now comes from Authly instead of being specified by the service.

### Fixed
- Turn off `rustls` default features.

## [0.0.7] - 2025-02-11
### Changed
- Make access control test-friendly with dynamically-dispatched `AccessControl` trait.
- `NamespacedPropertyAttribute` trait for making less verbose access control requests.
- `request_client_builder_stream` not async anymore.
- CSR API changed to accept any common name and explicit list of alternative names

### Added
- `ConnectionParams` now public, and added a stream of `Arc<ConnectionParam>` to the Client API.
- `metadata_stream` added to Client.

## [0.0.6] - 2025-02-04
### Changed
- Namespaces ("domains") added to access control API
- Service metadata redesigned and moved to separate module.

## [0.0.5] - 2025-01-30
### Added
- Background worker with auto-reconnect and messaging system
- rustls ServerConfig stream

## [0.0.4] - 2025-01-27
### Changed
- New standard paths for root and local CAs.

## [0.0.3] - 2025-01-22
### Changed
- Standard path of Authly CA is now /etc/authly/local/ca.crt.
- Kubernetes authentication URL is now https://authly-k8s/api/v0/authenticate.

### Added
- Support for inferring identity from /etc/authly/identity/identity.pem.
- Support for `AUTHLY_URL` environment variable.
- Method for decoding and verifying access token.
- Method for getting the current resource property mapping.
- Method for generating signed certificate and key pair for Authly mesh servers.

### Fixed
- Potention bug with order in identity PEMfile.