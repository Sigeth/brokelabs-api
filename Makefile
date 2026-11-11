IMG ?= ghcr.io/sigeth/opslab-api:dev
CONTAINER_TOOL ?= $(shell command -v podman >/dev/null 2>&1 && echo podman || echo docker)

.PHONY: all build run test lint deny openapi verify-generated image

all: lint test build

build:
	cargo build --release

## run: run locally on :8080 (OPSLAB_WEB_DIR=../web/dist to serve the UI)
run:
	cargo run

test:
	cargo test

lint:
	cargo fmt --check
	cargo clippy --all-targets -- -D warnings

deny:
	cargo deny check

## openapi: write the OpenAPI document (consumed by the web UI client generator)
openapi:
	cargo run --quiet -- --openapi > openapi.json

## verify-generated: fail if openapi.json is out of date (CI)
verify-generated: openapi
	git diff --exit-code -- openapi.json

image:
	$(CONTAINER_TOOL) build --platform linux/amd64 -t $(IMG) .
