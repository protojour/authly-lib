# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased
### Changed
- Standard path of Authly CA is now /etc/authly/local/ca.crt.

### Added
- Support for inferring identity from /etc/authly/identity/identity.pem.
- Support for `AUTHLY_URL` environment variable.
- Method for decoding and verifying access token.
- Method for getting the current resource property mapping.

### Fixed
- Potention bug with order in identity PEMfile.