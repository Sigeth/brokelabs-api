# opslab-api

The platform backend of opslab (working name). It handles users, classrooms, the challenge catalog, instance lifecycle and scoring, and it mints the short-lived access tokens the gateway verifies.

> Status: M0 skeleton.

## Endpoints

| Path | What |
|---|---|
| `GET /api/v1/version` | Version of the api |
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
| `RUST_LOG` | `info,tower_http=debug` | Log filter |

## Development

```sh
make lint test
make run                 # http://localhost:8080/api/v1/version
make openapi             # writes openapi.json for the web client generator
make image               # linux/amd64 (podman or docker)
```

The shared crates come from [opslab-core-rs](https://github.com/Sigeth/opslab-core-rs) by git tag.

## License

[MIT](LICENSE)
