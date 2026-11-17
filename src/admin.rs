//! Handlers of /api/v1/admin: the marketplace (catalog sources, installing,
//! updating and removing challenges). Admins only.
//!
//! The api only writes desired state (CatalogSource and Challenge objects):
//! the operator syncs, verifies, checks permissions and mirrors (D2, D40-D42).
//! Removals cascade to installed challenges and running instances (D43).

use std::collections::BTreeMap;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use kube::api::ObjectMeta;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use brokelabs_types::generated::catalogsources::{
    CatalogSourceSpec, CatalogSourceTrust, CatalogSourceTrustKeyless,
};
use brokelabs_types::generated::challengeinstances::ChallengeInstanceStatusPhase;
use brokelabs_types::generated::challenges::{
    ChallengeSource, ChallengeSourceCatalog, ChallengeSpec,
};
use brokelabs_types::{CatalogSource, Challenge, ChallengeInstance};

use crate::app::AppState;
use crate::auth::AdminUser;
use crate::error::{ApiError, ErrorBody};

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_catalogs, add_catalog))
        .routes(routes!(remove_catalog))
        .routes(routes!(marketplace))
        .routes(routes!(list_installed))
        .routes(routes!(install, remove_challenge))
}

type Result<T> = std::result::Result<T, ApiError>;

/// Who a catalog source trusts (D40).
#[derive(Serialize, Deserialize, ToSchema, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct TrustView {
    /// PEM public keys (cosign or `brokelabs challenge sign --key`).
    #[serde(default)]
    pub keys: Vec<String>,
    /// Sigstore keyless identities, e.g. a CI workflow.
    #[serde(default)]
    pub keyless: Vec<KeylessView>,
    /// Accepts unsigned packages. For local development only.
    #[serde(default)]
    pub allow_unsigned: bool,
}

/// A Sigstore keyless identity.
#[derive(Serialize, Deserialize, ToSchema, Clone)]
#[serde(rename_all = "camelCase")]
pub struct KeylessView {
    pub issuer: String,
    pub subject_reg_exp: String,
}

/// A catalog source and its last sync.
#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CatalogView {
    pub name: String,
    /// OCI reference of the catalog index.
    #[serde(rename = "ref")]
    pub reference: String,
    pub trust: TrustView,
    /// The last sync verified the index.
    pub ready: bool,
    /// Why the source is not ready, or what the last sync found.
    pub message: Option<String>,
    /// Who signed the index.
    pub signer: Option<String>,
    /// RFC 3339 time of the last successful sync.
    pub last_sync: Option<String>,
    /// Packages listed by the last verified index.
    pub packages: usize,
    /// Installed by the Helm chart (the official catalog): removing it here
    /// lasts until the next upgrade, unless the chart values disable it.
    pub managed_by_chart: bool,
}

/// A new catalog source.
#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct NewCatalog {
    /// Name of the source (a DNS label).
    pub name: String,
    /// OCI reference of the catalog index, e.g. "ghcr.io/school/catalog:latest".
    #[serde(rename = "ref")]
    pub reference: String,
    pub trust: TrustView,
}

/// What a package needs from the cluster, derived from it (D41).
#[derive(Serialize, Deserialize, ToSchema, Clone, PartialEq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct PermissionsView {
    /// Runtimes of its machines (pod, vm...).
    pub runtimes: Vec<String>,
    /// CPU of the machines of one instance, e.g. "1500m".
    pub cpu: String,
    /// Memory of the machines of one instance, e.g. "1536Mi".
    pub memory: String,
    /// Outbound network access: none, allowlist or internet.
    pub egress: String,
    #[serde(default)]
    pub egress_allowlist: Vec<String>,
    /// Kinds created by extra manifests in the instance namespace.
    #[serde(default)]
    pub extra_manifest_kinds: Vec<String>,
    /// Custom checker image, with access to the machines.
    pub checker_image: Option<String>,
}

/// A published version of a package.
#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PackageVersionView {
    pub version: String,
    pub permissions: Option<PermissionsView>,
}

/// An installed challenge, as the operator reports it.
#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct InstalledView {
    pub name: String,
    pub title: Option<String>,
    pub version: Option<String>,
    /// Where it comes from: catalog, oci or inline (development).
    pub source_kind: String,
    /// Catalog source, for catalog installs.
    pub catalog: Option<String>,
    /// Version asked for, for catalog installs (may not be installed yet).
    pub requested_version: Option<String>,
    /// Installed and verified.
    pub ready: bool,
    /// What the operator says about the installation.
    pub message: Option<String>,
    pub runnable: bool,
    pub unrunnable_reason: Option<String>,
    /// The package and its images are in the in-cluster registry mirror.
    pub mirrored: bool,
    /// Who signed the package.
    pub signer: Option<String>,
    pub permissions: Option<PermissionsView>,
    /// Instances that removing the challenge would stop.
    pub active_instances: usize,
}

/// A package offered by a catalog source.
#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MarketplaceEntry {
    /// Catalog source listing it.
    pub source: String,
    pub name: String,
    pub title: String,
    pub summary: Option<String>,
    pub category: String,
    pub difficulty: String,
    pub tags: Vec<String>,
    /// Versions, newest first.
    pub versions: Vec<PackageVersionView>,
    /// The installed challenge of the same name, if any (from this source or
    /// another one).
    pub installed: Option<InstalledView>,
    /// A newer version than the installed one is listed by this source.
    pub update_available: bool,
}

/// Installs or updates a challenge from a catalog source.
#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct InstallRequest {
    /// Catalog source listing the package.
    pub source: String,
    /// Version to install.
    pub version: String,
}

/// Catalog sources and their last sync.
#[utoipa::path(get, path = "/api/v1/admin/catalogs", tag = "marketplace",
    responses((status = 200, body = Vec<CatalogView>), (status = 403, body = ErrorBody)))]
async fn list_catalogs(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> Result<Json<Vec<CatalogView>>> {
    let mut list: Vec<CatalogView> = state
        .cluster
        .catalog_sources()
        .await?
        .iter()
        .map(catalog_view)
        .collect();
    list.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(Json(list))
}

/// Adds a catalog source. The operator syncs and verifies it.
#[utoipa::path(post, path = "/api/v1/admin/catalogs", tag = "marketplace", request_body = NewCatalog,
    responses((status = 201, body = CatalogView), (status = 400, body = ErrorBody),
        (status = 403, body = ErrorBody), (status = 409, body = ErrorBody)))]
async fn add_catalog(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    Json(req): Json<NewCatalog>,
) -> Result<(StatusCode, Json<CatalogView>)> {
    validate_name(&req.name)?;
    if req.reference.trim().is_empty() {
        return Err(ApiError::BadRequest(
            "the index reference is required".into(),
        ));
    }
    let trust = &req.trust;
    if trust.keys.is_empty() && trust.keyless.is_empty() && !trust.allow_unsigned {
        return Err(ApiError::BadRequest(
            "trust a key or a keyless identity (or allow unsigned packages, for development)"
                .into(),
        ));
    }
    let source = CatalogSource {
        metadata: ObjectMeta {
            name: Some(req.name.clone()),
            ..Default::default()
        },
        spec: CatalogSourceSpec {
            r#ref: req.reference.trim().to_string(),
            suspend: None,
            sync_interval: None,
            trust: CatalogSourceTrust {
                allow_unsigned: trust.allow_unsigned.then_some(true),
                keys: (!trust.keys.is_empty()).then(|| trust.keys.clone()),
                keyless: (!trust.keyless.is_empty()).then(|| {
                    trust
                        .keyless
                        .iter()
                        .map(|k| CatalogSourceTrustKeyless {
                            issuer: k.issuer.clone(),
                            subject_reg_exp: k.subject_reg_exp.clone(),
                        })
                        .collect()
                }),
            },
        },
        status: None,
    };
    let created = state.cluster.create_catalog_source(&source).await?;
    tracing::info!(
        admin = admin.username,
        source = req.name,
        r#ref = req.reference,
        "catalog source added"
    );
    Ok((StatusCode::CREATED, Json(catalog_view(&created))))
}

/// Removes a catalog source, the challenges installed from it and their
/// running instances (D43).
#[utoipa::path(delete, path = "/api/v1/admin/catalogs/{name}", tag = "marketplace",
    params(("name" = String, Path, description = "Catalog source name")),
    responses((status = 204), (status = 403, body = ErrorBody)))]
async fn remove_catalog(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    Path(name): Path<String>,
) -> Result<StatusCode> {
    state.cluster.delete_catalog_source(&name).await?;
    tracing::info!(
        admin = admin.username,
        source = name,
        "catalog source removed"
    );
    Ok(StatusCode::NO_CONTENT)
}

/// Packages listed by every catalog source, with what is installed.
#[utoipa::path(get, path = "/api/v1/admin/marketplace", tag = "marketplace",
    responses((status = 200, body = Vec<MarketplaceEntry>), (status = 403, body = ErrorBody)))]
async fn marketplace(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> Result<Json<Vec<MarketplaceEntry>>> {
    let installed = installed_by_name(&state).await?;
    let mut entries = Vec::new();
    for source in state.cluster.catalog_sources().await? {
        let source_name = source.metadata.name.clone().unwrap_or_default();
        let packages = source
            .status
            .as_ref()
            .and_then(|s| s.packages.clone())
            .unwrap_or_default();
        for p in packages {
            let versions: Vec<PackageVersionView> = p
                .versions
                .iter()
                .map(|v| PackageVersionView {
                    version: v.version.clone(),
                    permissions: permissions(&v.permissions),
                })
                .collect();
            let installed = installed.get(&p.name).map(Installed::view);
            let update_available = installed.as_ref().is_some_and(|i| {
                i.catalog.as_deref() == Some(source_name.as_str())
                    && i.version
                        .as_ref()
                        .zip(versions.first())
                        .is_some_and(|(have, newest)| newer(&newest.version, have))
            });
            entries.push(MarketplaceEntry {
                source: source_name.clone(),
                name: p.name.clone(),
                title: p.title.clone(),
                summary: p.summary.clone(),
                category: enum_str(&p.category),
                difficulty: enum_str(&p.difficulty),
                tags: p.tags.clone().unwrap_or_default(),
                versions,
                installed,
                update_available,
            });
        }
    }
    entries.sort_by(|a, b| (&a.title, &a.source).cmp(&(&b.title, &b.source)));
    Ok(Json(entries))
}

/// Installed challenges, whatever their source.
#[utoipa::path(get, path = "/api/v1/admin/challenges", tag = "marketplace",
    responses((status = 200, body = Vec<InstalledView>), (status = 403, body = ErrorBody)))]
async fn list_installed(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> Result<Json<Vec<InstalledView>>> {
    Ok(Json(
        installed_by_name(&state)
            .await?
            .values()
            .map(Installed::view)
            .collect(),
    ))
}

/// Installs a challenge from a catalog source, or moves it to another
/// version. The operator verifies the package against the trust policy of
/// the source and its permissions against the platform policy.
#[utoipa::path(put, path = "/api/v1/admin/challenges/{name}", tag = "marketplace", request_body = InstallRequest,
    params(("name" = String, Path, description = "Package name")),
    responses((status = 200, body = InstalledView), (status = 400, body = ErrorBody), (status = 403, body = ErrorBody),
        (status = 404, body = ErrorBody), (status = 409, body = ErrorBody)))]
async fn install(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    Path(name): Path<String>,
    Json(req): Json<InstallRequest>,
) -> Result<Json<InstalledView>> {
    validate_name(&name)?;
    let sources = state.cluster.catalog_sources().await?;
    let source = sources
        .iter()
        .find(|s| s.metadata.name.as_deref() == Some(req.source.as_str()))
        .ok_or_else(|| ApiError::NotFound(format!("catalog source {} not found", req.source)))?;
    let listed = source
        .status
        .as_ref()
        .and_then(|s| s.packages.as_ref())
        .and_then(|ps| ps.iter().find(|p| p.name == name))
        .is_some_and(|p| p.versions.iter().any(|v| v.version == req.version));
    if !listed {
        return Err(ApiError::NotFound(format!(
            "{name} {} is not listed by {}",
            req.version, req.source
        )));
    }
    if let Some(existing) = state.cluster.challenge(&name).await?
        && existing.spec.source.catalog.is_none()
    {
        return Err(ApiError::Conflict(format!(
            "{name} is installed from elsewhere ({}): remove it first",
            source_kind(&existing)
        )));
    }
    let challenge = Challenge {
        metadata: ObjectMeta {
            name: Some(name.clone()),
            ..Default::default()
        },
        spec: ChallengeSpec {
            disabled: None,
            source: ChallengeSource {
                catalog: Some(ChallengeSourceCatalog {
                    name: name.clone(),
                    source: req.source.clone(),
                    version: req.version.clone(),
                }),
                inline: None,
                oci: None,
            },
        },
        status: None,
    };
    let saved = state.cluster.put_challenge(&challenge).await?;
    tracing::info!(
        admin = admin.username,
        challenge = name,
        source = req.source,
        version = req.version,
        "challenge installed"
    );
    let active = count_active(&state.cluster.instances().await?, &name);
    Ok(Json(
        Installed {
            challenge: saved,
            active_instances: active,
        }
        .view(),
    ))
}

/// Removes a challenge and stops its running instances (D43). Scores stay.
#[utoipa::path(delete, path = "/api/v1/admin/challenges/{name}", tag = "marketplace",
    params(("name" = String, Path, description = "Challenge name")),
    responses((status = 204), (status = 403, body = ErrorBody)))]
async fn remove_challenge(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    Path(name): Path<String>,
) -> Result<StatusCode> {
    state.cluster.delete_challenge(&name).await?;
    tracing::info!(
        admin = admin.username,
        challenge = name,
        "challenge removed"
    );
    Ok(StatusCode::NO_CONTENT)
}

fn validate_name(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name.len() <= 63
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !name.starts_with('-')
        && !name.ends_with('-');
    if ok {
        Ok(())
    } else {
        Err(ApiError::BadRequest(format!(
            "{name:?}: use lowercase letters, digits and dashes (at most 63)"
        )))
    }
}

/// An installed challenge with its running instances.
struct Installed {
    challenge: Challenge,
    active_instances: usize,
}

impl Installed {
    fn view(&self) -> InstalledView {
        let ch = &self.challenge;
        let status = ch.status.as_ref();
        let pkg = status.and_then(|s| s.package.as_ref());
        let catalog = ch.spec.source.catalog.as_ref();
        let ready = condition(status.and_then(|s| s.conditions.as_deref()), "Ready");
        InstalledView {
            name: ch.metadata.name.clone().unwrap_or_default(),
            title: pkg.map(|p| p.spec.title.clone()),
            version: pkg.map(|p| p.metadata.version.clone()),
            source_kind: source_kind(ch).into(),
            catalog: catalog.map(|c| c.source.clone()),
            requested_version: catalog.map(|c| c.version.clone()),
            ready: ready.is_some_and(|c| c.status == "True"),
            message: ready.map(|c| c.message.clone()).filter(|m| !m.is_empty()),
            runnable: status.and_then(|s| s.runnable).unwrap_or(false),
            unrunnable_reason: status
                .and_then(|s| s.unrunnable_reason.clone())
                .filter(|r| !r.is_empty()),
            mirrored: status.and_then(|s| s.mirrored).unwrap_or(false),
            signer: status
                .and_then(|s| s.signer.clone())
                .filter(|s| !s.is_empty()),
            permissions: status
                .and_then(|s| s.permissions.as_ref())
                .and_then(permissions),
            active_instances: self.active_instances,
        }
    }
}

async fn installed_by_name(state: &AppState) -> Result<BTreeMap<String, Installed>> {
    let instances = state.cluster.instances().await?;
    Ok(state
        .cluster
        .challenges()
        .await?
        .into_iter()
        .filter_map(|c| {
            let name = c.metadata.name.clone()?;
            let active_instances = count_active(&instances, &name);
            Some((
                name,
                Installed {
                    challenge: c,
                    active_instances,
                },
            ))
        })
        .collect())
}

/// Instances of a challenge that are not over.
fn count_active(instances: &[ChallengeInstance], challenge: &str) -> usize {
    instances
        .iter()
        .filter(|i| i.spec.challenge == challenge)
        .filter(|i| {
            !matches!(
                i.status.as_ref().and_then(|s| s.phase.as_ref()),
                Some(ChallengeInstanceStatusPhase::Expired | ChallengeInstanceStatusPhase::Failed)
            )
        })
        .count()
}

fn source_kind(ch: &Challenge) -> &'static str {
    let src = &ch.spec.source;
    if src.catalog.is_some() {
        "catalog"
    } else if src.oci.is_some() {
        "oci"
    } else {
        "inline"
    }
}

fn catalog_view(cs: &CatalogSource) -> CatalogView {
    let status = cs.status.as_ref();
    let ready = condition(status.and_then(|s| s.conditions.as_deref()), "Ready");
    let trust = &cs.spec.trust;
    CatalogView {
        name: cs.metadata.name.clone().unwrap_or_default(),
        reference: cs.spec.r#ref.clone(),
        trust: TrustView {
            keys: trust.keys.clone().unwrap_or_default(),
            keyless: trust
                .keyless
                .iter()
                .flatten()
                .map(|k| KeylessView {
                    issuer: k.issuer.clone(),
                    subject_reg_exp: k.subject_reg_exp.clone(),
                })
                .collect(),
            allow_unsigned: trust.allow_unsigned.unwrap_or(false),
        },
        ready: ready.is_some_and(|c| c.status == "True"),
        message: ready.map(|c| c.message.clone()).filter(|m| !m.is_empty()),
        signer: status
            .and_then(|s| s.signer.clone())
            .filter(|s| !s.is_empty()),
        last_sync: status.and_then(|s| s.last_sync_time.clone()),
        packages: status.and_then(|s| s.packages.as_ref()).map_or(0, Vec::len),
        managed_by_chart: cs
            .metadata
            .labels
            .as_ref()
            .and_then(|l| l.get("app.kubernetes.io/managed-by"))
            // Tilt relabels what it applies from the chart (dev loop).
            .is_some_and(|m| m == "Helm" || m == "tilt"),
    }
}

fn condition<'a>(conditions: Option<&'a [Condition]>, kind: &str) -> Option<&'a Condition> {
    conditions?.iter().find(|c| c.type_ == kind)
}

/// Permissions from either generated type (catalog index or Challenge
/// status), which share their JSON form.
fn permissions<T: Serialize>(p: &T) -> Option<PermissionsView> {
    let mut value = serde_json::to_value(p).ok()?;
    for quantity in ["cpu", "memory"] {
        // Quantities are numbers or strings in JSON ("1" or 1).
        if let Some(v) = value.get_mut(quantity)
            && let Some(n) = v.as_i64()
        {
            *v = serde_json::Value::String(n.to_string());
        }
    }
    serde_json::from_value(value).ok()
}

fn enum_str<T: Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

/// Whether semantic version a is newer than b. Unparsable versions are
/// never newer.
fn newer(a: &str, b: &str) -> bool {
    fn parse(v: &str) -> Option<(u64, u64, u64, bool)> {
        let (core, pre) = match v.split_once('-') {
            Some((c, _)) => (c, true),
            None => (v.split('+').next().unwrap_or(v), false),
        };
        let mut parts = core.split('.').map(|p| p.parse::<u64>().ok());
        Some((parts.next()??, parts.next()??, parts.next()??, !pre))
    }
    matches!((parse(a), parse(b)), (Some(a), Some(b)) if a > b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semantic_versions() {
        assert!(newer("1.10.0", "1.9.0"));
        assert!(newer("1.0.0", "1.0.0-rc.1"));
        assert!(!newer("1.0.0", "1.0.0"));
        assert!(!newer("0.9.0", "1.0.0"));
        assert!(!newer("garbage", "1.0.0"));
    }

    #[test]
    fn names() {
        assert!(validate_name("ssh-hardening").is_ok());
        for bad in ["", "SSH", "-x", "x-", "a_b", &"a".repeat(64)] {
            assert!(validate_name(bad).is_err(), "{bad}");
        }
    }
}
