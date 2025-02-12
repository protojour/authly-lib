# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased
### Added
- public method to get peer service entity from MTLSMiddleware when not used with HTTP

## [0.0.7] - 2025-02-11
### Changed
- namespace level added to property mapping protobuf.
- decouple policies from services, introduce `domain` concept into document model.
- improved implementation of policy engine with new logical model for policy combinations.
- `entity-attribute-binding` renamed to `entity-attribute-assignment`. Now accepts only one parameter for identifying the entity.
- Protobuf definitions changed into using `authly.` package prefix.
- `Eid` removed, replaced by `PersonaId`, `GroupId`, `ServiceId` and their dynamic union: `EntityId`.

### Added
- x509 oid extension for Entity ID

## [0.0.5] - 2025-01-30
### Changed
- mandate submission reponse type

### Added
- authly_service.proto: Add client messaging

## [0.0.4] - 2025-01-27
### Added
- authly_connect and authly_mandate_submission services.

## [0.0.3] - 2025-01-22
### Changed
- `tower-server` updated to `0.3.x`.

### Added
- `mtls_server` utilities.
- `SignCertificate` rpc to `authly_service` protobuf.
