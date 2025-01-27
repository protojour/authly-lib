# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

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