# Quickstart

1. Install Rust (stable) via https://rustup.rs/
2. `cargo build --workspace`
3. Run the CLI: `cargo run -p cli -- --help`
4. Run the GUI: `cargo run -p gui`

### Notes
- GUI uses `iced` (pure Rust), so no Node or web stack is required.
- This is a skeleton: networking/MFA/policy features are scaffolded but not implemented yet.
