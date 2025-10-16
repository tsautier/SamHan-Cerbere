# Cerbère

**Type**: Passerelle d’accès RADIUS + MFA • **Langage**: Rust • **Interfaces**: CLI & GUI (multi‑OS) • **Licence**: MIT

## Objectifs
- Proxy d’authentification RADIUS centralisé (UDP/1812) pour VPN / Wi‑Fi / pare‑feux
- Auth primaire pluggable (fichier local, LDAP/AD — stub)
- MFA TOTP (enrôlement CLI/GUI, vérif côté serveur — en cours)
- Moteur de politiques simple (first‑match) et outils d’intégration
- Observabilité (tracing), limites de débit & lockout, audit minimal

> État : **MVP fonctionnel** — serveur RADIUS, loader de config, parser d’attributs, rate‑limit, TOTP enroll, GUI de base, snippets d’intégration.
> Des fonctionnalités sont stub/à compléter (LDAP réel, chaînage MFA/Policy vers décision).

## Structure (workspace)
- `crates/radius-core` — header/attributs RADIUS + serveur async + rate-limit
- `crates/policy-engine` — `config/policies/*.toml` (loader + eval)
- `crates/mfa-broker` — TOTP (HMAC‑SHA1), `otpauth://` URI
- `crates/id-connectors` — backend fichier Argon2 + LDAP (stub)
- `crates/storage` — config TOML (+ `env:` resolver), store TOTP JSON, audit/rotation
- `crates/telemetry` — init tracing (RUST_LOG) + sortie JSON optionnelle
- `crates/cli` — commandes: run/status/radius test/users/mfa/generate/audit
- `crates/gui` — UI iced (Status / Policies / MFA)

## Démarrage rapide
```bash
# Prérequis
rustup show  # Rust stable
export CERBERE_RADIUS_SECRET=changeme
export LDAP_BIND_PWD=changeme

# Build
cargo build --workspace

# Lancer le serveur
cargo run -p cli -- run --config ./config/cerbere.toml

# Auto‑test RADIUS
cargo run -p cli -- radius test --dest 127.0.0.1:1812 --id 7
# (option) simuler un code MFA
cargo run -p cli -- radius test --dest 127.0.0.1:1812 --id 7 --mfa-code 123456

# Utilisateurs (backend fichier)
cargo run -p cli -- users add --user alice --password secret
cargo run -p cli -- users list

# MFA TOTP (enrôlement)
cargo run -p cli -- mfa enroll --user alice
```

## Config
`config/cerbere.toml` (extrait) :
```toml
[server]
bind = "0.0.0.0:1812"
shared_secret = "env:CERBERE_RADIUS_SECRET"

[backend.primary]
type = "file"           # ou "ldap"
bind_password = "env:LDAP_BIND_PWD"
```

## Politique (exemple)
`config/policies/corp_default.toml` :
```toml
[[rules]]
when = "group == 'VPN-Users'"
action = "allow_mfa"

[[rules]]
when = "hour < 6 or hour > 22"
action = "require_strong_mfa"
```

## Build CI
- GitHub Actions (Linux/macOS/Windows) : build + test + clippy.
- Logs JSON facultatifs : `CERBERE_LOG_JSON=1` ; niveaux via `RUST_LOG`.

## Licence
MIT — voir [LICENSE](./LICENSE).
