# Cerbère (by SamHan)

Cerbère is a next‑gen RADIUS + MFA access gateway written in Rust.
It provides a CLI for automation and a cross‑platform GUI (iced).

> Status: project bootstrap (MVP skeleton).

## Crates (workspace)

- `radius-core` — RADIUS packet encode/decode + async server (skeleton)
- `policy-engine` — Declarative policy evaluation (skeleton)
- `mfa-broker` — Pluggable MFA abstraction (skeleton)
- `id-connectors` — AD/LDAP/SQL/File connectors (skeleton)
- `storage` — SQLite/PostgreSQL adapters (skeleton)
- `telemetry` — Logging / metrics / tracing (skeleton)
- `cli` — CLI entrypoint (`cerbere`)
- `gui` — Cross‑platform GUI (iced)

## Quick start

```bash
# Install Rust toolchain (stable)
# https://rustup.rs/

# Build everything
cargo build --workspace

# Run CLI
cargo run -p cli -- --help

# Run GUI
cargo run -p gui
```

## License
MIT © 2025 SamHan
