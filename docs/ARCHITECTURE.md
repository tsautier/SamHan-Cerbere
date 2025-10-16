# Architecture

Cerbère is a Rust workspace composed of several crates:

- `radius-core`: async UDP server skeleton + packet types
- `policy-engine`: rule model + future evaluator
- `mfa-broker`: traits for MFA providers (TOTP / WebAuthn / Push / OIDC)
- `id-connectors`: directories & SQL integrations
- `storage`: persistence layer (SQLite/PostgreSQL) via feature flags
- `telemetry`: tracing/logging/metrics

Entrypoints:
- CLI (`cli` crate)
- GUI (`gui` crate using iced)
