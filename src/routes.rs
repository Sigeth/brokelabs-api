//! Handlers of /api/v1.

use std::time::{Duration, SystemTime};

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum_extra::extract::CookieJar;
use brokelabs_auth::{AccessGrant, AccessKind, DEFAULT_TTL};
use brokelabs_types::generated::challengeinstances::{
    ChallengeInstanceOwner, ChallengeInstanceSpec, ChallengeInstanceStatusPhase,
};
use brokelabs_types::generated::checkruns::CheckRunSpec;
use brokelabs_types::{ChallengeInstance, CheckRun};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{ObjectMeta, OwnerReference};
use kube::Resource;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use uuid::Uuid;

use crate::app::AppState;
use crate::auth::{self, CurrentUser};
use crate::db;
use crate::error::{ApiError, ErrorBody};
use crate::views::{self, *};

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(login))
        .routes(routes!(logout))
        .routes(routes!(me))
        .routes(routes!(settings))
        .merge(crate::users::router())
        .merge(crate::oidc::router())
        .routes(routes!(list_challenges))
        .routes(routes!(get_challenge))
        .routes(routes!(list_instances, start_instance))
        .routes(routes!(get_instance, stop_instance))
        .routes(routes!(open_terminal))
        .routes(routes!(latest_check, start_check))
        .merge(crate::admin::router())
}

type Result<T> = std::result::Result<T, ApiError>;

/// Signs in with a local account.
#[utoipa::path(post, path = "/api/v1/auth/login", tag = "auth", request_body = LoginRequest,
    responses((status = 200, body = Me), (status = 401, body = ErrorBody)))]
async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(req): Json<LoginRequest>,
) -> Result<(CookieJar, Json<Me>)> {
    let user = db::user_by_name(&state.db, &req.username).await?;
    let valid = match &user {
        Some(u) => auth::verify_password(
            &req.password,
            u.password_hash.as_deref().unwrap_or_default(),
        ),
        None => {
            // Same cost whether or not the user exists.
            let _ = auth::hash_password(&req.password);
            false
        }
    };
    let (Some(user), true) = (user, valid) else {
        return Err(ApiError::Unauthorized);
    };
    if user.disabled_at.is_some() {
        return Err(ApiError::Forbidden(
            "this account is disabled: ask an administrator".into(),
        ));
    }
    let cookie = auth::login(&state.db, &user, state.config.cookie_secure).await?;
    db::record_login(&state.db, user.id).await?;
    let me = me_of(&state, user).await?;
    Ok((jar.add(cookie), Json(me)))
}

/// Signs out.
#[utoipa::path(post, path = "/api/v1/auth/logout", tag = "auth", responses((status = 204)))]
async fn logout(State(state): State<AppState>, jar: CookieJar) -> Result<(CookieJar, StatusCode)> {
    let removal = auth::logout(&state.db, &jar).await?;
    Ok((jar.add(removal), StatusCode::NO_CONTENT))
}

async fn me_of(state: &AppState, user: db::User) -> Result<Me> {
    Ok(Me {
        score: db::score(&state.db, user.id).await?,
        sso: user.oidc_subject.is_some(),
        id: user.id,
        username: user.username,
        display_name: user.display_name,
        role: user.role,
    })
}

/// The signed-in user and their score.
#[utoipa::path(get, path = "/api/v1/me", tag = "auth",
    responses((status = 200, body = Me), (status = 401, body = ErrorBody)))]
async fn me(State(state): State<AppState>, CurrentUser(user): CurrentUser) -> Result<Json<Me>> {
    Ok(Json(me_of(&state, user).await?))
}

/// How the platform is set up, for the web UI (no sign-in needed).
#[utoipa::path(get, path = "/api/v1/settings", tag = "meta",
    responses((status = 200, body = Settings)))]
async fn settings(State(state): State<AppState>) -> Json<Settings> {
    Json(Settings {
        mode: state.config.mode,
        sso: state.oidc.as_ref().map(|o| SsoSettings {
            label: o.config.label.clone(),
            roles_from_provider: o.config.manages_roles(),
        }),
    })
}

/// Installed challenges, with the user's progress.
#[utoipa::path(get, path = "/api/v1/challenges", tag = "catalog",
    responses((status = 200, body = Vec<ChallengeSummary>)))]
async fn list_challenges(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
) -> Result<Json<Vec<ChallengeSummary>>> {
    let solves = db::solves(&state.db, user.id).await?;
    let mut list: Vec<ChallengeSummary> = state
        .cluster
        .challenges()
        .await?
        .iter()
        .filter(|c| !c.spec.disabled.unwrap_or(false))
        .filter_map(|c| views::summary(c, &solves))
        .collect();
    list.sort_by(|a, b| {
        (difficulty_rank(&a.difficulty), &a.title).cmp(&(difficulty_rank(&b.difficulty), &b.title))
    });
    Ok(Json(list))
}

fn difficulty_rank(d: &str) -> usize {
    ["easy", "medium", "hard", "insane"]
        .iter()
        .position(|x| *x == d)
        .unwrap_or(9)
}

/// A challenge, with its instructions and tasks.
#[utoipa::path(get, path = "/api/v1/challenges/{name}", tag = "catalog",
    params(("name" = String, Path, description = "Challenge name")),
    responses((status = 200, body = ChallengeDetail), (status = 404, body = ErrorBody)))]
async fn get_challenge(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
    Path(name): Path<String>,
) -> Result<Json<ChallengeDetail>> {
    let not_found = || ApiError::NotFound(format!("challenge {name} is not installed"));
    let ch = state
        .cluster
        .challenge(&name)
        .await?
        .ok_or_else(not_found)?;
    if ch.spec.disabled.unwrap_or(false) {
        return Err(not_found());
    }
    let solves = db::solves(&state.db, user.id).await?;
    let pkg = views::package(&ch).ok_or_else(not_found)?;
    Ok(Json(ChallengeDetail {
        instructions: state.cluster.instructions(&ch).await?,
        task_list: views::tasks(pkg, &name, &solves),
        terminals: views::terminals(pkg),
        summary: views::summary(&ch, &solves).ok_or_else(not_found)?,
    }))
}

/// The user's active instances.
#[utoipa::path(get, path = "/api/v1/instances", tag = "instances",
    responses((status = 200, body = Vec<InstanceView>)))]
async fn list_instances(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
) -> Result<Json<Vec<InstanceView>>> {
    let mut out = Vec::new();
    for attempt in db::active_attempts(&state.db, user.id).await? {
        match state.cluster.instance(&attempt.instance_name).await? {
            Some(ci) => out.push(instance_view(&state, &ci).await?),
            // Deleted behind our back: the watcher will end the attempt too.
            None => db::end_attempt(&state.db, &attempt.instance_name, "deleted").await?,
        }
    }
    Ok(Json(out))
}

pub async fn instance_view(state: &AppState, ci: &ChallengeInstance) -> Result<InstanceView> {
    let ch = state.cluster.challenge(&ci.spec.challenge).await?;
    let terminals = ch
        .as_ref()
        .and_then(views::package)
        .map(views::terminals)
        .unwrap_or_default();
    Ok(views::instance(ci, terminals))
}

/// Starts a challenge. A user has one active instance at a time.
#[utoipa::path(post, path = "/api/v1/instances", tag = "instances", request_body = StartInstance,
    responses((status = 201, body = InstanceView), (status = 404, body = ErrorBody), (status = 409, body = ErrorBody)))]
async fn start_instance(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
    Json(req): Json<StartInstance>,
) -> Result<(StatusCode, Json<InstanceView>)> {
    let ch = state
        .cluster
        .challenge(&req.challenge)
        .await?
        .filter(|c| !c.spec.disabled.unwrap_or(false))
        .ok_or_else(|| {
            ApiError::NotFound(format!("challenge {} is not installed", req.challenge))
        })?;
    let pkg = views::package(&ch)
        .ok_or_else(|| ApiError::Conflict("the challenge is not ready".into()))?;
    if !ch.status.as_ref().and_then(|s| s.runnable).unwrap_or(false) {
        return Err(ApiError::Conflict(
            "this cluster cannot run the challenge".into(),
        ));
    }

    let id = Uuid::new_v4();
    let prefix: String = req.challenge.chars().take(40).collect();
    let name = format!(
        "{}-{}",
        prefix.trim_end_matches('-'),
        &id.simple().to_string()[..8]
    );
    let attempt = db::create_attempt(
        &state.db,
        id,
        user.id,
        &req.challenge,
        &pkg.metadata.version,
        &name,
    )
    .await
    .map_err(|e| match db::is_unique_violation(&e) {
        true => ApiError::Conflict("stop your running instance first".into()),
        false => e.into(),
    })?;

    let instance = ChallengeInstance {
        metadata: ObjectMeta {
            name: Some(name),
            namespace: Some(state.config.instances_namespace.clone()),
            ..Default::default()
        },
        spec: ChallengeInstanceSpec {
            challenge: req.challenge.clone(),
            owner: ChallengeInstanceOwner {
                user_id: user.id.to_string(),
                display_name: Some(user.display_name.clone()),
            },
            expires_at: None,
        },
        status: None,
    };
    match state.cluster.create_instance(&instance).await {
        Ok(created) => Ok((
            StatusCode::CREATED,
            Json(views::instance(&created, views::terminals(pkg))),
        )),
        Err(e) => {
            db::delete_attempt(&state.db, attempt.id).await?;
            Err(e.into())
        }
    }
}

/// Looks up an active attempt of the user.
async fn own_attempt(state: &AppState, user: &db::User, id: &str) -> Result<db::Attempt> {
    db::attempt_by_instance(&state.db, id)
        .await?
        .filter(|a| a.user_id == user.id && a.ended_at.is_none())
        .ok_or_else(|| ApiError::NotFound(format!("no active instance {id}")))
}

async fn own_instance(
    state: &AppState,
    user: &db::User,
    id: &str,
) -> Result<(db::Attempt, ChallengeInstance)> {
    let attempt = own_attempt(state, user, id).await?;
    let ci = state
        .cluster
        .instance(id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("instance {id} is gone")))?;
    Ok((attempt, ci))
}

/// An instance of the user.
#[utoipa::path(get, path = "/api/v1/instances/{id}", tag = "instances",
    params(("id" = String, Path, description = "Instance ID")),
    responses((status = 200, body = InstanceView), (status = 404, body = ErrorBody)))]
async fn get_instance(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
    Path(id): Path<String>,
) -> Result<Json<InstanceView>> {
    let (_, ci) = own_instance(&state, &user, &id).await?;
    Ok(Json(instance_view(&state, &ci).await?))
}

/// Stops an instance. Everything in it is lost; scores are kept.
#[utoipa::path(delete, path = "/api/v1/instances/{id}", tag = "instances",
    params(("id" = String, Path, description = "Instance ID")),
    responses((status = 204), (status = 404, body = ErrorBody)))]
async fn stop_instance(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
    Path(id): Path<String>,
) -> Result<StatusCode> {
    own_attempt(&state, &user, &id).await?;
    state.cluster.delete_instance(&id).await?;
    db::end_attempt(&state.db, &id, "stopped").await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Opens a terminal: returns the gateway URL with a short-lived token.
#[utoipa::path(post, path = "/api/v1/instances/{id}/terminals", tag = "instances",
    params(("id" = String, Path, description = "Instance ID")), request_body = OpenTerminal,
    responses((status = 200, body = TerminalAccess), (status = 404, body = ErrorBody), (status = 409, body = ErrorBody)))]
async fn open_terminal(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
    Path(id): Path<String>,
    Json(req): Json<OpenTerminal>,
) -> Result<Json<TerminalAccess>> {
    let (_, ci) = own_instance(&state, &user, &id).await?;
    if ci.status.as_ref().and_then(|s| s.phase.as_ref())
        != Some(&ChallengeInstanceStatusPhase::Ready)
    {
        return Err(ApiError::Conflict("the instance is not ready".into()));
    }
    let ch = state.cluster.challenge(&ci.spec.challenge).await?;
    let terminal = ch
        .as_ref()
        .and_then(views::package)
        .and_then(|p| {
            p.spec
                .access
                .terminals
                .iter()
                .find(|t| t.machine == req.machine)
                .cloned()
        })
        .ok_or_else(|| ApiError::NotFound(format!("no terminal on machine {}", req.machine)))?;
    let grant = AccessGrant {
        user_id: user.id.to_string(),
        instance: format!("{}/{id}", state.config.instances_namespace),
        machine: terminal.machine,
        kind: AccessKind::Terminal {
            user: terminal.user.unwrap_or_else(|| "student".into()),
        },
    };
    let token = state
        .signer
        .sign(&grant, SystemTime::now(), DEFAULT_TTL)
        .map_err(|e| ApiError::Internal(e.into()))?;
    Ok(Json(TerminalAccess {
        url: state.config.terminal_url(&token),
    }))
}

pub fn check_view(run: &db::CheckRun, instance: &str, newly_solved: Vec<String>) -> CheckRunView {
    let phase = match run.phase.as_str() {
        "Running" => CheckPhase::Running,
        "Completed" => CheckPhase::Completed,
        "Error" => CheckPhase::Error,
        _ => CheckPhase::Pending,
    };
    CheckRunView {
        id: run.name.clone(),
        instance: instance.to_string(),
        phase,
        message: run.message.clone(),
        results: run
            .results
            .as_ref()
            .map(|r| {
                r.0.iter()
                    .map(|r| TaskResultView {
                        task: r.task.clone(),
                        passed: r.passed,
                        message: r.message.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default(),
        newly_solved,
    }
}

/// The latest check of an instance.
#[utoipa::path(get, path = "/api/v1/instances/{id}/checks", tag = "instances",
    params(("id" = String, Path, description = "Instance ID")),
    responses((status = 200, body = Option<CheckRunView>), (status = 404, body = ErrorBody)))]
async fn latest_check(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
    Path(id): Path<String>,
) -> Result<Json<Option<CheckRunView>>> {
    let attempt = own_attempt(&state, &user, &id).await?;
    let run = db::latest_check_run(&state.db, attempt.id).await?;
    Ok(Json(run.map(|r| check_view(&r, &id, vec![]))))
}

/// Checks every task of an instance. Results arrive as events.
#[utoipa::path(post, path = "/api/v1/instances/{id}/checks", tag = "instances",
    params(("id" = String, Path, description = "Instance ID")),
    responses((status = 202, body = CheckRunView), (status = 404, body = ErrorBody), (status = 409, body = ErrorBody)))]
async fn start_check(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<CheckRunView>)> {
    let (attempt, ci) = own_instance(&state, &user, &id).await?;
    if ci.status.as_ref().and_then(|s| s.phase.as_ref())
        != Some(&ChallengeInstanceStatusPhase::Ready)
    {
        return Err(ApiError::Conflict("the instance is not ready".into()));
    }
    if let Some(last) = db::latest_check_run(&state.db, attempt.id).await? {
        let recent = time::OffsetDateTime::now_utc() - last.requested_at < Duration::from_secs(180);
        if matches!(last.phase.as_str(), "Pending" | "Running") && recent {
            return Err(ApiError::Conflict("a check is already running".into()));
        }
    }
    let n = db::count_check_runs(&state.db, attempt.id).await? + 1;
    let name = format!("{id}-{n}");
    let row = db::create_check_run(&state.db, attempt.id, &name).await?;
    let run = CheckRun {
        metadata: ObjectMeta {
            name: Some(name),
            namespace: Some(state.config.instances_namespace.clone()),
            // Deleted with the instance.
            owner_references: Some(vec![OwnerReference {
                api_version: ChallengeInstance::api_version(&()).into(),
                kind: ChallengeInstance::kind(&()).into(),
                name: id.clone(),
                uid: ci.metadata.uid.clone().unwrap_or_default(),
                ..Default::default()
            }]),
            ..Default::default()
        },
        spec: CheckRunSpec {
            instance: id.clone(),
            tasks: None,
        },
        status: None,
    };
    if let Err(e) = state.cluster.create_check_run(&run).await {
        db::delete_check_run(&state.db, row.id).await?;
        return Err(e.into());
    }
    Ok((StatusCode::ACCEPTED, Json(check_view(&row, &id, vec![]))))
}
