//! Configuration, read from environment variables.

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Context;

/// Runtime configuration of the api.
#[derive(Clone, Debug)]
pub struct Config {
    /// Address to listen on (`OPSLAB_LISTEN`, default `0.0.0.0:8080`).
    pub listen: SocketAddr,
    /// Directory of the built web UI, served for every non-API path
    /// (`OPSLAB_WEB_DIR`, optional).
    pub web_dir: Option<PathBuf>,
    /// PKCS#8 PEM file of the access token signing key
    /// (`OPSLAB_SIGNING_KEY_FILE`). Without it, an ephemeral key is generated:
    /// tokens then stop verifying when the api restarts.
    pub signing_key_file: Option<PathBuf>,
    /// Log as JSON lines (`OPSLAB_LOG_FORMAT=json`) instead of human-readable text.
    pub log_json: bool,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    fn from_lookup(get: impl Fn(&str) -> Option<String>) -> anyhow::Result<Self> {
        let listen = get("OPSLAB_LISTEN").unwrap_or_else(|| "0.0.0.0:8080".into());
        Ok(Self {
            listen: listen
                .parse()
                .with_context(|| format!("OPSLAB_LISTEN: invalid address {listen:?}"))?,
            web_dir: get("OPSLAB_WEB_DIR").map(PathBuf::from),
            signing_key_file: get("OPSLAB_SIGNING_KEY_FILE").map(PathBuf::from),
            log_json: get("OPSLAB_LOG_FORMAT").as_deref() == Some("json"),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn config(vars: &[(&str, &str)]) -> anyhow::Result<Config> {
        let vars: HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Config::from_lookup(|k| vars.get(k).cloned())
    }

    #[test]
    fn defaults() {
        let c = config(&[]).unwrap();
        assert_eq!(c.listen.port(), 8080);
        assert!(c.web_dir.is_none() && c.signing_key_file.is_none() && !c.log_json);
    }

    #[test]
    fn rejects_invalid_listen_address() {
        assert!(config(&[("OPSLAB_LISTEN", "localhost")]).is_err());
    }
}
