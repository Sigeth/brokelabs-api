# Static (musl) binary on distroless/static: no shell, no package manager,
# runs as an unprivileged user.
FROM docker.io/library/rust:1.99-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY migrations migrations
COPY src src
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release && cp target/release/brokelabs-api /brokelabs-api

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /brokelabs-api /brokelabs-api
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/brokelabs-api"]
