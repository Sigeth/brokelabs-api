# brokelabs-api

The platform backend of BrokeLabs. It handles users, classrooms, the challenge catalog, instance lifecycle and scoring, and it mints the short-lived access tokens the gateway verifies.

> Status: M5 in progress. Solo and organization modes, local accounts with roles and user management, catalog and marketplace, instances, terminals, checks and scores.

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
| anything else | The web UI, when `BROKELABS_WEB_DIR` is set (single-page app fallback to `index.html`) |

## Configuration

| Variable | Default | |
|---|---|---|
| `BROKELABS_LISTEN` | `0.0.0.0:8080` | Listen address |
| `BROKELABS_WEB_DIR` | none | Built web UI to serve |
| `BROKELABS_SIGNING_KEY_FILE` | ephemeral key | PKCS#8 PEM Ed25519 key signing access tokens |
| `BROKELABS_LOG_FORMAT` | text | `json` for JSON logs |
| `BROKELABS_DATABASE_URL` (or `_FILE`) | required | PostgreSQL URL. Migrations run at startup. |
| `BROKELABS_INSTANCES_NAMESPACE` | `brokelabs-instances` | Namespace of `ChallengeInstance`s and `CheckRun`s |
| `BROKELABS_SYSTEM_NAMESPACE` | `brokelabs-system` | Namespace of the platform (inline package files) |
| `BROKELABS_GATEWAY_URL` | `http://localhost:8081` | Public URL of the gateway, as browsers reach it |
| `BROKELABS_ALLOWED_ORIGINS` | none | Comma-separated origins allowed to send state-changing requests (CSRF). Set it to the platform URL. |
| `BROKELABS_COOKIE_SECURE` | `true` | `Secure` session cookies (browsers accept them on http://localhost) |
| `BROKELABS_PUBLIC_URL` | `http://localhost:8080` | Platform URL as browsers reach it (single sign-on redirects) |
| `BROKELABS_OIDC_ISSUER` | unset | OpenID Connect issuer: enables single sign-on. With `BROKELABS_OIDC_CLIENT_ID`, `BROKELABS_OIDC_CLIENT_SECRET_FILE` (or `_SECRET`; none for a public client), `BROKELABS_OIDC_LABEL`, `BROKELABS_OIDC_SCOPES`, `BROKELABS_OIDC_GROUPS_CLAIM` (default `groups`, dots for nested claims), `BROKELABS_OIDC_ADMIN_GROUPS` / `BROKELABS_OIDC_TEACHER_GROUPS` (comma-separated: the provider then decides roles at every sign-in) `BROKELABS_OIDC_CA_FILE` and `BROKELABS_OIDC_BACKCHANNEL_URL` (the api's address of the provider when it differs from the issuer's) |
| `BROKELABS_MODE` | `solo` | `solo` (one person) or `organization` (accounts, roles and classrooms) |
| `BROKELABS_ADMIN_USERNAME` | `admin` | First admin account, created when there is no user (the only one in solo mode) |
| `BROKELABS_ADMIN_PASSWORD_FILE` (or `BROKELABS_ADMIN_PASSWORD`) | generated, logged once | First admin's password. When set, it is authoritative. |
| `RUST_LOG` | `info,tower_http=debug` | Log filter |

## Development

```sh
make lint test           # database tests run when BROKELABS_TEST_DATABASE_URL is set
make run                 # http://localhost:8080/api/v1/version
make openapi             # writes openapi.json for the web client generator
make image               # linux/amd64 (podman or docker)
```

The shared crates come from [brokelabs-core-rs](https://github.com/Sigeth/brokelabs-core-rs) by git tag.

## License

[MIT](LICENSE)
