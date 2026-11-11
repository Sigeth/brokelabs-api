//! opslab api: the platform backend.
//!
//! `opslab-api --openapi` prints the OpenAPI document and exits (used to
//! generate the web UI's TypeScript client).

mod app;
mod auth;
mod cluster;
mod config;
mod db;
mod error;
mod events;
mod routes;
mod views;

#[cfg(test)]
mod handler_tests;

use std::sync::Arc;

use anyhow::Context;
use opslab_auth::Signer;
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

use crate::app::AppState;
use crate::config::Config;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if std::env::args().any(|a| a == "--openapi") {
        println!("{}", app::openapi().to_pretty_json()?);
        return Ok(());
    }

    let config = Config::from_env()?;
    init_tracing(config.log_json);

    let signer = match &config.signing_key_file {
        Some(path) => {
            let pem = std::fs::read_to_string(path)
                .with_context(|| format!("reading signing key {}", path.display()))?;
            Signer::from_pkcs8_pem(&pem)?
        }
        None => {
            tracing::warn!("OPSLAB_SIGNING_KEY_FILE is not set: using an ephemeral signing key");
            Signer::generate()?
        }
    };
    tracing::info!(key_id = signer.key_id(), "access token signing key loaded");

    let db = db::connect(&config.database_url)
        .await
        .context("connecting to the database")?;
    auth::bootstrap_solo(&db, &config.solo_username, config.solo_password.as_deref()).await?;

    let client = kube::Client::try_default()
        .await
        .context("connecting to Kubernetes")?;
    let cluster = cluster::Kube {
        client: client.clone(),
        instances_namespace: config.instances_namespace.clone(),
        system_namespace: config.system_namespace.clone(),
    };
    let state = AppState {
        signer: Arc::new(signer),
        db,
        cluster: Arc::new(cluster),
        hub: events::Hub::default(),
        config: Arc::new(config.clone()),
    };
    tokio::spawn(events::watch(state.clone(), client));

    let app = app::router(state, config.web_dir.as_deref());
    let listener = TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("binding {}", config.listen))?;
    tracing::info!(address = %config.listen, "listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

fn init_tracing(json: bool) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,tower_http=debug"));
    let builder = tracing_subscriber::fmt().with_env_filter(filter);
    if json {
        builder.json().init();
    } else {
        builder.init();
    }
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("installing the SIGTERM handler");
    tokio::select! {
        _ = ctrl_c => {},
        _ = term.recv() => {},
    }
    tracing::info!("shutting down");
}
