//! Configuration, read from environment variables.

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, bail};
use brokelabs_types::project;

/// Runtime configuration of the api.
#[derive(Clone, Debug)]
pub struct Config {
    /// Address to listen on (`BROKELABS_LISTEN`, default `0.0.0.0:8080`).
    pub listen: SocketAddr,
    /// Directory of the built web UI, served for every non-API path
    /// (`BROKELABS_WEB_DIR`, optional).
    pub web_dir: Option<PathBuf>,
    /// PKCS#8 PEM file of the access token signing key
    /// (`BROKELABS_SIGNING_KEY_FILE`). Without it, an ephemeral key is generated:
    /// tokens then stop verifying when the api restarts.
    pub signing_key_file: Option<PathBuf>,
    /// Log as JSON lines (`BROKELABS_LOG_FORMAT=json`) instead of human-readable text.
    pub log_json: bool,
    /// PostgreSQL connection URL (`BROKELABS_DATABASE_URL`, required), or a file
    /// holding it (`BROKELABS_DATABASE_URL_FILE`).
    pub database_url: String,
    /// Namespace of ChallengeInstances and CheckRuns (`BROKELABS_INSTANCES_NAMESPACE`).
    pub instances_namespace: String,
    /// Namespace of the platform, holding inline package files
    /// (`BROKELABS_SYSTEM_NAMESPACE`, default `brokelabs-system`).
    pub system_namespace: String,
    /// Public URL of the gateway, as browsers reach it (`BROKELABS_GATEWAY_URL`,
    /// e.g. `https://gw.brokelabs.example.org`).
    pub gateway_url: String,
    /// Origins allowed to send state-changing requests with the session
    /// cookie (`BROKELABS_ALLOWED_ORIGINS`, comma-separated, e.g. the public URL
    /// of the platform). Empty disables the check (development only).
    pub allowed_origins: Vec<String>,
    /// Session cookies are `Secure` (`BROKELABS_COOKIE_SECURE`, default true;
    /// browsers accept secure cookies on http://localhost).
    pub cookie_secure: bool,
    /// How the install is used (`BROKELABS_MODE`: `solo`, the default, or
    /// `organization`).
    pub mode: Mode,
    /// First admin, created when there is no user yet
    /// (`BROKELABS_ADMIN_USERNAME`, default `admin`). In solo mode, the only user.
    pub admin_username: String,
    /// Password of the first admin (`BROKELABS_ADMIN_PASSWORD_FILE` or
    /// `BROKELABS_ADMIN_PASSWORD`). When set, it is authoritative: the user's
    /// password is reset to it at startup.
    pub admin_password: Option<String>,
}

/// How an install is used (D12).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// One person running it for themselves: no user management or classrooms.
    Solo,
    /// A school or team: accounts, roles and classrooms.
    Organization,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    fn from_lookup(get: impl Fn(&str) -> Option<String>) -> anyhow::Result<Self> {
        let read_file = |var: &str| -> anyhow::Result<Option<String>> {
            get(var)
                .map(|path| {
                    std::fs::read_to_string(&path)
                        .map(|s| s.trim().to_string())
                        .with_context(|| format!("{var}: reading {path}"))
                })
                .transpose()
        };
        let listen = get("BROKELABS_LISTEN").unwrap_or_else(|| "0.0.0.0:8080".into());
        let database_url = match read_file("BROKELABS_DATABASE_URL_FILE")? {
            Some(url) => url,
            None => get("BROKELABS_DATABASE_URL").unwrap_or_default(),
        };
        if database_url.is_empty() {
            bail!("BROKELABS_DATABASE_URL (or BROKELABS_DATABASE_URL_FILE) is required");
        }
        let gateway_url =
            get("BROKELABS_GATEWAY_URL").unwrap_or_else(|| "http://localhost:8081".into());
        if !(gateway_url.starts_with("http://") || gateway_url.starts_with("https://")) {
            bail!("BROKELABS_GATEWAY_URL must be an http(s) URL, got {gateway_url:?}");
        }
        Ok(Self {
            listen: listen
                .parse()
                .with_context(|| format!("BROKELABS_LISTEN: invalid address {listen:?}"))?,
            web_dir: get("BROKELABS_WEB_DIR").map(PathBuf::from),
            signing_key_file: get("BROKELABS_SIGNING_KEY_FILE").map(PathBuf::from),
            log_json: get("BROKELABS_LOG_FORMAT").as_deref() == Some("json"),
            database_url,
            instances_namespace: get("BROKELABS_INSTANCES_NAMESPACE")
                .unwrap_or_else(|| project::INSTANCES_NAMESPACE.into()),
            system_namespace: get("BROKELABS_SYSTEM_NAMESPACE")
                .unwrap_or_else(|| format!("{}-system", project::NAME)),
            gateway_url: gateway_url.trim_end_matches('/').to_string(),
            allowed_origins: get("BROKELABS_ALLOWED_ORIGINS")
                .unwrap_or_default()
                .split(',')
                .map(|o| o.trim().trim_end_matches('/').to_string())
                .filter(|o| !o.is_empty())
                .collect(),
            cookie_secure: get("BROKELABS_COOKIE_SECURE").as_deref() != Some("false"),
            mode: match get("BROKELABS_MODE").as_deref() {
                None | Some("solo") => Mode::Solo,
                Some("organization") => Mode::Organization,
                Some(other) => bail!("BROKELABS_MODE must be solo or organization, got {other:?}"),
            },
            admin_username: get("BROKELABS_ADMIN_USERNAME").unwrap_or_else(|| "admin".into()),
            admin_password: match read_file("BROKELABS_ADMIN_PASSWORD_FILE")? {
                Some(p) => Some(p),
                None => get("BROKELABS_ADMIN_PASSWORD"),
            },
        })
    }

    /// Configuration from explicit variables (tests).
    #[cfg(test)]
    pub fn from_env_map(vars: &[(&str, &str)]) -> anyhow::Result<Self> {
        let vars: std::collections::HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Self::from_lookup(|k| vars.get(k).cloned())
    }

    /// WebSocket URL of the gateway's terminal endpoint.
    pub fn terminal_url(&self, token: &str) -> String {
        let base = self
            .gateway_url
            .replacen("https://", "wss://", 1)
            .replacen("http://", "ws://", 1);
        format!("{base}/v1/terminal?token={token}")
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn config(vars: &[(&str, &str)]) -> anyhow::Result<Config> {
        let mut vars: HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        vars.entry("BROKELABS_DATABASE_URL".into())
            .or_insert_with(|| "postgres://localhost/brokelabs".into());
        Config::from_lookup(|k| vars.get(k).cloned())
    }

    #[test]
    fn defaults() {
        let c = config(&[]).unwrap();
        assert_eq!(c.listen.port(), 8080);
        assert!(c.web_dir.is_none() && c.signing_key_file.is_none() && !c.log_json);
        assert_eq!(c.instances_namespace, "brokelabs-instances");
        assert_eq!(c.system_namespace, "brokelabs-system");
        assert!(c.cookie_secure && c.allowed_origins.is_empty());
        assert_eq!(c.mode, Mode::Solo);
        assert_eq!(c.admin_username, "admin");
    }

    #[test]
    fn rejects_invalid_values() {
        assert!(config(&[("BROKELABS_LISTEN", "localhost")]).is_err());
        assert!(config(&[("BROKELABS_GATEWAY_URL", "gw.example.org")]).is_err());
        assert!(config(&[("BROKELABS_DATABASE_URL", "")]).is_err());
        assert!(config(&[("BROKELABS_MODE", "school")]).is_err());
        assert_eq!(
            config(&[("BROKELABS_MODE", "organization")]).unwrap().mode,
            Mode::Organization
        );
    }

    #[test]
    fn terminal_urls_use_websockets() {
        let c = config(&[("BROKELABS_GATEWAY_URL", "https://gw.example.org/")]).unwrap();
        assert_eq!(
            c.terminal_url("t"),
            "wss://gw.example.org/v1/terminal?token=t"
        );
        let c = config(&[("BROKELABS_ALLOWED_ORIGINS", "https://a.org/, https://b.org")]).unwrap();
        assert_eq!(c.allowed_origins, ["https://a.org", "https://b.org"]);
    }
}
