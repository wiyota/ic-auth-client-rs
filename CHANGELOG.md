# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

## [0.4.0-alpha] - 2025-04-16

### Added

- `AuthClient` and `IdleManager` are now thread-safe.

### Changed

- **(Breaking)** Updated `ic-agent` dependency to **v0.40**.
  This version is **not** compatible with previous versions.

### Removed

- **(Breaking)** Removed `IdentityType`.
  Use `ArcIdentity` as a replacement.

### Refactored

- **(Breaking)** Reorganized some internal build patterns.
  These changes may impact specific build or integration scenarios.

## [0.3.1] - 2024-11-14

- Relaxed version specification of dependencies.
- Improved inner error handling.

## [0.3.0] - 2024-11-11

- Breaking: Updated dependency to `ic-agent` v0.39. Not compatible with previous versions.
- Using `ed25519-consensus` instead of `ring` to create `BasicIdentity`.
- Removes warning that users found unhelpful, when a message originates from other sources than the identity provider during authentication.

## [0.2.1] - 2024-09-24

- Updated dependency to `ic-agent` v0.38.

## [0.2.0] - 2024-09-11

- Breaking: `AuthClient::login()` and `AuthClient::login_with_options()` become synchronous.
