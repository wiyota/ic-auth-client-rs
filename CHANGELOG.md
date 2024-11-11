# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

## [0.3.0] - 2024-11-11

- Breaking: Updated dependency to `ic-agent` v0.39. Not compatible with previous versions.
- Using `ed25519-consensus` instead of `ring` to create `BasicIdentity`.
- Removes warning that users found unhelpful, when a message originates from other sources than the identity provider during authentication.

## [0.2.1] - 2024-09-24

- Updated dependency to `ic-agent` v0.38.

## [0.2.0] - 2024-09-11

- Breaking: `AuthClient::login()` and `AuthClient::login_with_options()` become synchronous.
