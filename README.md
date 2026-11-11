# opslab-api

The platform backend of opslab (working name). It handles users, classrooms, the challenge catalog, instance lifecycle and scoring, and it mints the short-lived access tokens the gateway verifies.

> Status: M1. Solo mode (one local admin account), catalog, instances, terminals, checks and scores.

The api is the source of truth for **people and progress** (PostgreSQL). Kubernetes is the source of truth for **running things**: the api creates `ChallengeInstance` and `CheckRun` resources and watches what the operator reports. It never calls the operator directly.

## Endpoints

| Path | What |
|---|---|
| `GET /api/v1/version` | Version of the api |
| `POST /api/v1/auth/login`, `POST /api/v1/auth/logout`, `GET /api/v1/me` | Local accounts, cookie sessions |
| `GET /api/v1/challenges[/{name}]` | Catalog with the user's progress, instructions and tasks |
| `GET/POST /api/v1/instances`, `GET/DELETE /api/v1/instances/{id}` | Start (one active instance per user), inspect and stop instances |
| `POST /api/v1/instances/{id}/terminals` | Gateway WebSocket URL with a 2-minute access token |
| `GET/POST /api/v1/instances/{id}/checks` | Latest check, start a check |
| `GET /api/v1/events` | Server-sent events: instance and check updates of the user |
| `GET /api/openapi.json` | OpenAPI document (source of the web UI's TypeScript client) |
| `GET /.well-known/jwks.json` | Public keys verifying access tokens (fetched by the gateway) |
| `GET /healthz` | Liveness |
| anything else | The web UI, when `OPSLAB_WEB_DIR` is set (single-page app fallback to `index.html`) |

## Configuration

| Variable | Default | |
|---|---|---|
| `OPSLAB_LISTEN` | `0.0.0.0:8080` | Listen address |
| `OPSLAB_WEB_DIR` | none | Built web UI to serve |
| `OPSLAB_SIGNING_KEY_FILE` | ephemeral key | PKCS#8 PEM Ed25519 key signing access tokens |
| `OPSLAB_LOG_FORMAT` | text | `json` for JSON logs |
| `OPSLAB_DATABASE_URL` (or `_FILE`) | required | PostgreSQL URL. Migrations run at startup. |
| `OPSLAB_INSTANCES_NAMESPACE` | `opslab-instances` | Namespace of `ChallengeInstance`s and `CheckRun`s |
| `OPSLAB_SYSTEM_NAMESPACE` | `opslab-system` | Namespace of the platform (inline package files) |
| `OPSLAB_GATEWAY_URL` | `http://localhost:8081` | Public URL of the gateway, as browsers reach it |
| `OPSLAB_ALLOWED_ORIGINS` | none | Comma-separated origins allowed to send state-changing requests (CSRF). Set it to the platform URL. |
| `OPSLAB_COOKIE_SECURE` | `true` | `Secure` session cookies (browsers accept them on http://localhost) |
| `OPSLAB_SOLO_USERNAME` | `admin` | Solo mode account, created on first start |
| `OPSLAB_SOLO_PASSWORD_FILE` (or `OPSLAB_SOLO_PASSWORD`) | generated, logged once | Solo mode password. When set, it is authoritative. |
| `RUST_LOG` | `info,tower_http=debug` | Log filter |

## Development

```sh
make lint test           # database tests run when OPSLAB_TEST_DATABASE_URL is set
make run                 # http://localhost:8080/api/v1/version
make openapi             # writes openapi.json for the web client generator
make image               # linux/amd64 (podman or docker)
```

The shared crates come from [opslab-core-rs](https://github.com/Sigeth/opslab-core-rs) by git tag.

## License

[MIT](LICENSE)
