# Observabilité & télémétrie

Cerbère publie désormais des traces et métriques via OpenTelemetry (OTLP gRPC) en plus des journaux JSON/texte.

## Activation

Définir la variable d'environnement `CERBERE_OTEL_ENDPOINT` (ex. `http://otel-collector:4317`).

Options complémentaires :

- `CERBERE_SERVICE_NAME` (défaut `cerbere`) pour personnaliser `service.name`.
- `CERBERE_OTEL_INTERVAL_SECS` (défaut 10 s) pour l'intervalle d'export métrique.
- `CERBERE_OTEL_TIMEOUT_MS` (défaut 5000 ms) pour le timeout réseau des exports traces/métriques.
- `CERBERE_LOG_JSON=1` pour forcer les logs JSON.

Le runtime utilise OTLP gRPC (tonic) et envoie :

- Des traces `tracing` converties via `tracing-opentelemetry`.
- Des compteurs/gauges RADIUS (requêtes, Access-Accept/Reject/Challenge, taux d'échec MFA, défis actifs…).

## Métriques exposées

| Nom | Type | Description |
| --- | --- | --- |
| `cerbere.radius.access_requests_total` | Counter | Nombre total de paquets Access-Request traités |
| `cerbere.radius.access_accept_total` | Counter | Nombre de réponses Access-Accept envoyées |
| `cerbere.radius.access_reject_total` | Counter | Nombre de réponses Access-Reject envoyées |
| `cerbere.radius.access_challenge_total` | Counter | Nombre de réponses Access-Challenge envoyées |
| `cerbere.radius.rate_limit_dropped_total` | Counter | Paquets rejetés par le rate-limit |
| `cerbere.radius.mfa_attempts_total` | Counter | Tentatives de vérification MFA reçues |
| `cerbere.radius.mfa_success_total` | Counter | MFA validées |
| `cerbere.radius.mfa_failure_total` | Counter | MFA échouées / expirées |
| `cerbere.radius.active_challenges` | UpDownCounter | Nombre de défis MFA actifs |

Les métriques sont envoyées via un `PeriodicReader` (intervalle configurable) ; les traces sont poussées via un batch processor asynchrone.

Pensez à fermer proprement le binaire pour permettre le flush (`Ctrl+C` déclenche la fermeture du runtime Tokio, le drop du guard force le flush des providers).
