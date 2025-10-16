# Security

- This repository is in early stage. Do not use in production.
- When adding crypto or secret management, prefer audited crates and constant‑time operations.
- Enable `RUSTFLAGS="-C target-cpu=native"` only when appropriate.
- Use `cargo audit` in CI to detect vulnerable dependencies.
