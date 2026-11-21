//! User management (admins, /api/v1/admin/users) and the user's own password.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum_extra::extract::CookieJar;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use uuid::Uuid;

use crate::app::AppState;
use crate::auth::{self, AdminUser, CurrentUser, ROLES, SESSION_COOKIE};
use crate::db;
use crate::error::{ApiError, ErrorBody};

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_users, create_user))
        .routes(routes!(update_user, delete_user))
        .routes(routes!(reset_password))
        .routes(routes!(change_password))
}

type Result<T> = std::result::Result<T, ApiError>;

/// Shortest password a user may choose.
const MIN_PASSWORD_LENGTH: usize = 8;
/// Random bytes of a generated password (16 characters).
const GENERATED_PASSWORD_BYTES: usize = 12;

/// An account, as admins see it.
#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UserView {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    /// admin, teacher or student.
    pub role: String,
    pub disabled: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub last_login_at: Option<OffsetDateTime>,
    /// Points of every solved task.
    pub score: i64,
    /// Signs in with single sign-on (no local password).
    pub sso: bool,
    /// From the sign-on provider.
    pub email: Option<String>,
}

impl From<db::UserRow> for UserView {
    fn from(u: db::UserRow) -> Self {
        Self {
            id: u.id,
            username: u.username,
            display_name: u.display_name,
            role: u.role,
            disabled: u.disabled_at.is_some(),
            created_at: u.created_at,
            last_login_at: u.last_login_at,
            score: u.score,
            sso: u.oidc_subject.is_some(),
            email: u.email,
        }
    }
}

#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateUser {
    /// Lowercase letters, digits, `.`, `_` and `-`, up to 64 characters.
    pub username: String,
    /// Defaults to the username.
    pub display_name: Option<String>,
    /// admin, teacher or student.
    pub role: String,
}

/// A new account and its generated password, shown once.
#[derive(Serialize, ToSchema)]
pub struct CreatedUser {
    pub user: UserView,
    pub password: String,
}

/// Fields to change; missing fields are kept.
#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UpdateUser {
    pub display_name: Option<String>,
    pub role: Option<String>,
    /// A disabled user cannot sign in; their sessions and instances end.
    pub disabled: Option<bool>,
}

/// A new generated password, shown once.
#[derive(Serialize, ToSchema)]
pub struct NewPassword {
    pub password: String,
}

#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ChangePassword {
    pub current_password: String,
    /// At least 8 characters.
    pub new_password: String,
}

pub fn validate_username(name: &str) -> Result<()> {
    let valid = !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "._-".contains(c))
        && name.starts_with(|c: char| c.is_ascii_alphanumeric());
    match valid {
        true => Ok(()),
        false => Err(ApiError::BadRequest(
            "a username is up to 64 lowercase letters, digits, '.', '_' or '-', starting with a letter or digit".into(),
        )),
    }
}

pub fn validate_display_name(name: &str) -> Result<&str> {
    let name = name.trim();
    match (1..=100).contains(&name.chars().count()) {
        true => Ok(name),
        false => Err(ApiError::BadRequest(
            "a display name has 1 to 100 characters".into(),
        )),
    }
}

pub fn validate_password(password: &str) -> Result<()> {
    match password.chars().count() >= MIN_PASSWORD_LENGTH {
        true => Ok(()),
        false => Err(ApiError::BadRequest(format!(
            "a password has at least {MIN_PASSWORD_LENGTH} characters"
        ))),
    }
}

fn validate_role(role: &str) -> Result<()> {
    match ROLES.contains(&role) {
        true => Ok(()),
        false => Err(ApiError::BadRequest(format!(
            "role must be one of {}",
            ROLES.join(", ")
        ))),
    }
}

fn parse_id(id: &str) -> Result<Uuid> {
    Uuid::parse_str(id).map_err(|_| ApiError::NotFound(format!("no user {id}")))
}

async fn user_view(state: &AppState, id: Uuid) -> Result<UserView> {
    db::user_row(&state.db, id)
        .await?
        .map(UserView::from)
        .ok_or_else(|| ApiError::NotFound(format!("no user {id}")))
}

/// Stops the running instances of a user (disabled or deleted).
async fn stop_instances(state: &AppState, user: Uuid, reason: &str) -> Result<()> {
    for attempt in db::active_attempts(&state.db, user).await? {
        state
            .cluster
            .delete_instance(&attempt.instance_name)
            .await?;
        db::end_attempt(&state.db, &attempt.instance_name, reason).await?;
    }
    Ok(())
}

/// Every account.
#[utoipa::path(get, path = "/api/v1/admin/users", tag = "admin",
    responses((status = 200, body = Vec<UserView>), (status = 403, body = ErrorBody)))]
async fn list_users(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> Result<Json<Vec<UserView>>> {
    let users = db::list_users(&state.db).await?;
    Ok(Json(users.into_iter().map(UserView::from).collect()))
}

/// Creates an account with a generated password, returned once.
#[utoipa::path(post, path = "/api/v1/admin/users", tag = "admin", request_body = CreateUser,
    responses((status = 201, body = CreatedUser), (status = 400, body = ErrorBody),
              (status = 403, body = ErrorBody), (status = 409, body = ErrorBody)))]
async fn create_user(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    Json(req): Json<CreateUser>,
) -> Result<(StatusCode, Json<CreatedUser>)> {
    let username = req.username.trim().to_lowercase();
    validate_username(&username)?;
    validate_role(&req.role)?;
    let display_name = validate_display_name(req.display_name.as_deref().unwrap_or(&username))?;
    let password = auth::random_token(GENERATED_PASSWORD_BYTES);
    let user = db::create_user(
        &state.db,
        &username,
        display_name,
        &req.role,
        &auth::hash_password(&password)?,
    )
    .await
    .map_err(|e| match db::is_unique_violation(&e) {
        true => ApiError::Conflict(format!("the username {username} is taken")),
        false => e.into(),
    })?;
    tracing::info!(
        admin = admin.username,
        username,
        role = req.role,
        "user created"
    );
    Ok((
        StatusCode::CREATED,
        Json(CreatedUser {
            user: user_view(&state, user.id).await?,
            password,
        }),
    ))
}

/// Changes a user's display name, role or state. Admins cannot change their
/// own role or disable themselves, so there is always an admin left.
#[utoipa::path(patch, path = "/api/v1/admin/users/{id}", tag = "admin", request_body = UpdateUser,
    params(("id" = String, Path, description = "User ID")),
    responses((status = 200, body = UserView), (status = 400, body = ErrorBody),
              (status = 403, body = ErrorBody), (status = 404, body = ErrorBody)))]
async fn update_user(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    Path(id): Path<String>,
    Json(req): Json<UpdateUser>,
) -> Result<Json<UserView>> {
    let id = parse_id(&id)?;
    let user = db::user_by_id(&state.db, id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("no user {id}")))?;
    if let Some(role) = &req.role {
        validate_role(role)?;
    }
    let display_name = req
        .display_name
        .as_deref()
        .map(validate_display_name)
        .transpose()?;
    if id == admin.id
        && (req.role.as_deref().is_some_and(|r| r != user.role) || req.disabled == Some(true))
    {
        return Err(ApiError::BadRequest(
            "you cannot change your own role or disable yourself".into(),
        ));
    }
    db::update_user(
        &state.db,
        id,
        display_name,
        req.role.as_deref(),
        req.disabled,
    )
    .await?;
    if req.disabled == Some(true) && user.disabled_at.is_none() {
        db::delete_sessions(&state.db, id, None).await?;
        stop_instances(&state, id, "user disabled").await?;
    }
    tracing::info!(
        admin = admin.username,
        username = user.username,
        role = req.role,
        disabled = req.disabled,
        "user updated"
    );
    Ok(Json(user_view(&state, id).await?))
}

/// Deletes an account with its progress and scores, and stops its instances.
#[utoipa::path(delete, path = "/api/v1/admin/users/{id}", tag = "admin",
    params(("id" = String, Path, description = "User ID")),
    responses((status = 204), (status = 400, body = ErrorBody),
              (status = 403, body = ErrorBody), (status = 404, body = ErrorBody)))]
async fn delete_user(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    Path(id): Path<String>,
) -> Result<StatusCode> {
    let id = parse_id(&id)?;
    if id == admin.id {
        return Err(ApiError::BadRequest("you cannot delete yourself".into()));
    }
    let user = db::user_by_id(&state.db, id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("no user {id}")))?;
    // Listed first: the delete removes the attempts with the user.
    let running = db::active_attempts(&state.db, id).await?;
    db::delete_user(&state.db, id).await.map_err(|e| {
        match db::violates(&e, "classrooms_owner_id_fkey") {
            true => ApiError::Conflict(format!(
                "{} owns classrooms: give them to another teacher or delete them first",
                user.username
            )),
            false => e.into(),
        }
    })?;
    // After the delete: a refused delete leaves the user's instances running.
    for attempt in running {
        state
            .cluster
            .delete_instance(&attempt.instance_name)
            .await?;
    }
    tracing::info!(
        admin = admin.username,
        username = user.username,
        "user deleted"
    );
    Ok(StatusCode::NO_CONTENT)
}

/// Gives a user a new generated password, returned once, and ends their sessions.
#[utoipa::path(post, path = "/api/v1/admin/users/{id}/password", tag = "admin",
    params(("id" = String, Path, description = "User ID")),
    responses((status = 200, body = NewPassword), (status = 403, body = ErrorBody),
              (status = 404, body = ErrorBody)))]
async fn reset_password(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    Path(id): Path<String>,
) -> Result<Json<NewPassword>> {
    let id = parse_id(&id)?;
    let user = db::user_by_id(&state.db, id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("no user {id}")))?;
    if user.oidc_subject.is_some() {
        return Err(ApiError::BadRequest(
            "this account signs in with single sign-on: it has no password".into(),
        ));
    }
    let password = auth::random_token(GENERATED_PASSWORD_BYTES);
    db::set_password(&state.db, id, &auth::hash_password(&password)?).await?;
    if id != admin.id {
        db::delete_sessions(&state.db, id, None).await?;
    }
    tracing::info!(
        admin = admin.username,
        username = user.username,
        "password reset"
    );
    Ok(Json(NewPassword { password }))
}

/// Changes the signed-in user's password and ends their other sessions.
#[utoipa::path(post, path = "/api/v1/me/password", tag = "auth", request_body = ChangePassword,
    responses((status = 204), (status = 400, body = ErrorBody), (status = 403, body = ErrorBody)))]
async fn change_password(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
    jar: CookieJar,
    Json(req): Json<ChangePassword>,
) -> Result<StatusCode> {
    if user.oidc_subject.is_some() {
        return Err(ApiError::BadRequest(
            "your account signs in with single sign-on: change your password there".into(),
        ));
    }
    if !auth::verify_password(
        &req.current_password,
        user.password_hash.as_deref().unwrap_or_default(),
    ) {
        return Err(ApiError::Forbidden("the current password is wrong".into()));
    }
    validate_password(&req.new_password)?;
    db::set_password(&state.db, user.id, &auth::hash_password(&req.new_password)?).await?;
    let current = jar.get(SESSION_COOKIE).map(|c| auth::token_hash(c.value()));
    db::delete_sessions(&state.db, user.id, current.as_deref()).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usernames() {
        for ok in ["alice", "a.b-c_d", "42", "x"] {
            assert!(validate_username(ok).is_ok(), "{ok}");
        }
        for bad in ["", "Alice", "-a", ".a", "a b", "é", &"a".repeat(65)] {
            assert!(validate_username(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn display_names_and_roles() {
        assert_eq!(validate_display_name("  Alice  ").unwrap(), "Alice");
        assert!(validate_display_name("   ").is_err());
        assert!(validate_display_name(&"x".repeat(101)).is_err());
        assert!(validate_role("teacher").is_ok());
        assert!(validate_role("root").is_err());
    }
}
