//! Classrooms (M5): teachers manage them under /api/v1/teach, students see
//! the ones they joined, and invite links let people join (D55).

use std::collections::BTreeMap;

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
use crate::auth::{self, CurrentUser, STUDENT_ROLE, TeacherUser};
use crate::config::Mode;
use crate::db::{self, classrooms as cdb};
use crate::error::{ApiError, ErrorBody};
use crate::views::{self, ChallengeSummary, Me};

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(my_classrooms))
        .routes(routes!(get_invite))
        .routes(routes!(join))
        .routes(routes!(sign_up))
        .routes(routes!(list_teaching, create_classroom))
        .routes(routes!(get_teaching, update_classroom, delete_classroom))
        .routes(routes!(rotate_invite))
        .routes(routes!(remove_member))
        .routes(routes!(put_assignment, delete_assignment))
}

type Result<T> = std::result::Result<T, ApiError>;

/// Characters of invite codes: no 0/O, 1/I/L, so they can be typed.
const CODE_ALPHABET: &[u8] = b"23456789ABCDEFGHJKMNPQRSTUVWXYZ";
const CODE_LENGTH: usize = 8;

fn new_invite_code() -> String {
    (0..CODE_LENGTH)
        .map(|_| CODE_ALPHABET[rand::random_range(0..CODE_ALPHABET.len())] as char)
        .collect()
}

/// A code as people type or paste it: any case, with or without the dash.
fn normalize_code(code: &str) -> String {
    code.chars()
        .filter(|c| !matches!(c, '-' | ' '))
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

/// `ABCD-EFGH`, as shown to people.
fn display_code(code: &str) -> String {
    match code.len() {
        CODE_LENGTH => format!("{}-{}", &code[..4], &code[4..]),
        _ => code.to_string(),
    }
}

fn organization_only(state: &AppState) -> Result<()> {
    match state.config.mode {
        Mode::Organization => Ok(()),
        Mode::Solo => Err(ApiError::Forbidden(
            "classrooms are off in solo mode".into(),
        )),
    }
}

fn validate_name(name: &str) -> Result<&str> {
    let name = name.trim();
    match (1..=100).contains(&name.chars().count()) {
        true => Ok(name),
        false => Err(ApiError::BadRequest(
            "a classroom name has 1 to 100 characters".into(),
        )),
    }
}

fn validate_description(text: &str) -> Result<&str> {
    let text = text.trim();
    match text.chars().count() <= 2000 {
        true => Ok(text),
        false => Err(ApiError::BadRequest(
            "a description has at most 2000 characters".into(),
        )),
    }
}

fn parse_id(id: &str) -> Result<Uuid> {
    Uuid::parse_str(id).map_err(|_| ApiError::NotFound(format!("no classroom {id}")))
}

// ---- Views ----

/// A classroom, as its teacher sees it.
#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ClassroomView {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub owner_id: Uuid,
    pub owner_name: String,
    /// `ABCD-EFGH`: the invite link is `/join/<code>`.
    pub invite_code: String,
    /// When false, the invite link does not work (members stay).
    pub invite_enabled: bool,
    pub members: i64,
    pub assignments: i64,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

impl From<cdb::Classroom> for ClassroomView {
    fn from(c: cdb::Classroom) -> Self {
        Self {
            id: c.id,
            name: c.name,
            description: c.description,
            owner_id: c.owner_id,
            owner_name: c.owner_name,
            invite_code: display_code(&c.invite_code),
            invite_enabled: c.invite_enabled,
            members: c.members,
            assignments: c.assignments,
            created_at: c.created_at,
        }
    }
}

/// A member of a classroom.
#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MemberView {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    #[serde(with = "time::serde::rfc3339")]
    pub joined_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub last_login_at: Option<OffsetDateTime>,
}

/// A challenge assigned to a classroom.
#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AssignmentView {
    pub challenge: String,
    /// The challenge's title, when it is still installed.
    pub title: Option<String>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub opens_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub due_at: Option<OffsetDateTime>,
}

/// A classroom with its members and assignments, for its teacher.
#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ClassroomDetail {
    pub classroom: ClassroomView,
    pub members: Vec<MemberView>,
    pub assignments: Vec<AssignmentView>,
}

/// An assignment, as a student sees it, with their progress.
#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct StudentAssignment {
    pub challenge: String,
    /// None when the challenge is no longer installed.
    pub summary: Option<ChallengeSummary>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub opens_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub due_at: Option<OffsetDateTime>,
    /// Every task is solved.
    pub done: bool,
    /// A task was solved after the deadline (it still counts, D58).
    pub late: bool,
}

/// A classroom the student joined.
#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct StudentClassroom {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub teacher: String,
    pub assignments: Vec<StudentAssignment>,
}

/// What an invite link leads to (no sign-in needed).
#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct InviteView {
    pub classroom: String,
    pub teacher: String,
}

/// The result of joining through an invite link.
#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct Joined {
    pub classroom_id: Uuid,
    /// False when the user was a member already.
    pub joined: bool,
}

#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SignUp {
    pub display_name: String,
    pub username: String,
    /// At least 8 characters.
    pub password: String,
}

#[derive(Deserialize, ToSchema)]
pub struct NewClassroom {
    pub name: String,
    pub description: Option<String>,
}

/// Fields to change; missing fields are kept.
#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ClassroomChange {
    pub name: Option<String>,
    pub description: Option<String>,
    pub invite_enabled: Option<bool>,
    /// New owner, a teacher or an admin (admins only).
    pub owner_id: Option<Uuid>,
}

/// Dates of an assignment; both optional.
#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AssignmentDates {
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub opens_at: Option<OffsetDateTime>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub due_at: Option<OffsetDateTime>,
}

// ---- Students ----

/// Builds the student view of classrooms, with the user's progress.
async fn student_view(
    state: &AppState,
    user: Uuid,
    classrooms: Vec<cdb::Classroom>,
) -> Result<Vec<StudentClassroom>> {
    let ids: Vec<Uuid> = classrooms.iter().map(|c| c.id).collect();
    let mut by_classroom: BTreeMap<Uuid, Vec<cdb::Assignment>> = BTreeMap::new();
    for a in cdb::assignments(&state.db, &ids).await? {
        by_classroom.entry(a.classroom_id).or_default().push(a);
    }
    let solves = db::solves(&state.db, user).await?;
    let challenges = state.cluster.challenges().await?;
    let summary = |name: &str| {
        challenges
            .iter()
            .filter(|c| !c.spec.disabled.unwrap_or(false))
            .find(|c| c.metadata.name.as_deref() == Some(name))
            .and_then(|c| views::summary(c, &solves))
    };
    Ok(classrooms
        .into_iter()
        .map(|c| StudentClassroom {
            assignments: by_classroom
                .remove(&c.id)
                .unwrap_or_default()
                .into_iter()
                .map(|a| {
                    let summary = summary(&a.challenge);
                    let late = a.due_at.is_some_and(|due| {
                        solves
                            .iter()
                            .any(|s| s.challenge == a.challenge && s.solved_at > due)
                    });
                    StudentAssignment {
                        done: summary
                            .as_ref()
                            .is_some_and(|s| s.tasks > 0 && s.solved_tasks >= s.tasks),
                        late,
                        summary,
                        challenge: a.challenge,
                        opens_at: a.opens_at,
                        due_at: a.due_at,
                    }
                })
                .collect(),
            id: c.id,
            name: c.name,
            description: c.description,
            teacher: c.owner_name,
        })
        .collect())
}

/// Classrooms the user joined, with their assignments and the user's progress.
#[utoipa::path(get, path = "/api/v1/classrooms", tag = "classrooms",
    responses((status = 200, body = Vec<StudentClassroom>)))]
async fn my_classrooms(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
) -> Result<Json<Vec<StudentClassroom>>> {
    if state.config.mode == Mode::Solo {
        return Ok(Json(Vec::new()));
    }
    let joined = cdb::joined(&state.db, user.id).await?;
    Ok(Json(student_view(&state, user.id, joined).await?))
}

/// The classroom of an enabled invite link.
async fn invited(state: &AppState, code: &str) -> Result<cdb::Classroom> {
    organization_only(state)?;
    cdb::by_invite_code(&state.db, &normalize_code(code))
        .await?
        .filter(|c| c.invite_enabled)
        .ok_or_else(|| ApiError::NotFound("this invite link is not valid or was turned off".into()))
}

/// What an invite link leads to. No sign-in needed.
#[utoipa::path(get, path = "/api/v1/invites/{code}", tag = "classrooms",
    params(("code" = String, Path, description = "Invite code")),
    responses((status = 200, body = InviteView), (status = 404, body = ErrorBody)))]
async fn get_invite(
    State(state): State<AppState>,
    Path(code): Path<String>,
) -> Result<Json<InviteView>> {
    let c = invited(&state, &code).await?;
    Ok(Json(InviteView {
        classroom: c.name,
        teacher: c.owner_name,
    }))
}

/// Joins the classroom of an invite link.
#[utoipa::path(post, path = "/api/v1/invites/{code}/join", tag = "classrooms",
    params(("code" = String, Path, description = "Invite code")),
    responses((status = 200, body = Joined), (status = 404, body = ErrorBody)))]
async fn join(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
    Path(code): Path<String>,
) -> Result<Json<Joined>> {
    let c = invited(&state, &code).await?;
    let joined = cdb::add_member(&state.db, c.id, user.id).await?;
    if joined {
        tracing::info!(
            username = user.username,
            classroom = c.name,
            "joined a classroom"
        );
    }
    Ok(Json(Joined {
        classroom_id: c.id,
        joined,
    }))
}

/// Creates a student account through an invite link, joins the classroom
/// and signs in.
#[utoipa::path(post, path = "/api/v1/invites/{code}/signup", tag = "classrooms",
    params(("code" = String, Path, description = "Invite code")), request_body = SignUp,
    responses((status = 201, body = Me), (status = 400, body = ErrorBody),
              (status = 404, body = ErrorBody), (status = 409, body = ErrorBody)))]
async fn sign_up(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(code): Path<String>,
    Json(req): Json<SignUp>,
) -> Result<(StatusCode, CookieJar, Json<Me>)> {
    let c = invited(&state, &code).await?;
    let username = req.username.trim().to_lowercase();
    crate::users::validate_username(&username)?;
    let display_name = crate::users::validate_display_name(&req.display_name)?;
    crate::users::validate_password(&req.password)?;
    let user = db::create_user(
        &state.db,
        &username,
        display_name,
        STUDENT_ROLE,
        &auth::hash_password(&req.password)?,
    )
    .await
    .map_err(|e| match db::is_unique_violation(&e) {
        true => ApiError::Conflict(format!("the username {username} is taken: choose another")),
        false => e.into(),
    })?;
    cdb::add_member(&state.db, c.id, user.id).await?;
    tracing::info!(
        username,
        classroom = c.name,
        "signed up through an invite link"
    );
    let cookie = auth::login(&state.db, &user, state.config.cookie_secure).await?;
    db::record_login(&state.db, user.id).await?;
    let me = crate::routes::me_of(&state, user).await?;
    Ok((StatusCode::CREATED, jar.add(cookie), Json(me)))
}

// ---- Teachers ----

/// A classroom the teacher may manage: their own, or any for admins.
pub async fn managed(state: &AppState, teacher: &TeacherUser, id: &str) -> Result<cdb::Classroom> {
    organization_only(state)?;
    let id = parse_id(id)?;
    cdb::get(&state.db, id)
        .await?
        .filter(|c| teacher.is_admin() || c.owner_id == teacher.0.id)
        .ok_or_else(|| ApiError::NotFound(format!("no classroom {id}")))
}

async fn classroom_view(state: &AppState, id: Uuid) -> Result<ClassroomView> {
    cdb::get(&state.db, id)
        .await?
        .map(ClassroomView::from)
        .ok_or_else(|| ApiError::NotFound(format!("no classroom {id}")))
}

/// Classrooms the teacher manages (every classroom for admins).
#[utoipa::path(get, path = "/api/v1/teach/classrooms", tag = "teach",
    responses((status = 200, body = Vec<ClassroomView>), (status = 403, body = ErrorBody)))]
async fn list_teaching(
    State(state): State<AppState>,
    teacher: TeacherUser,
) -> Result<Json<Vec<ClassroomView>>> {
    organization_only(&state)?;
    let owner = (!teacher.is_admin()).then_some(teacher.0.id);
    let list = cdb::list(&state.db, owner).await?;
    Ok(Json(list.into_iter().map(ClassroomView::from).collect()))
}

/// Creates a classroom owned by the teacher, with its invite link on.
#[utoipa::path(post, path = "/api/v1/teach/classrooms", tag = "teach", request_body = NewClassroom,
    responses((status = 201, body = ClassroomView), (status = 400, body = ErrorBody),
              (status = 403, body = ErrorBody)))]
async fn create_classroom(
    State(state): State<AppState>,
    teacher: TeacherUser,
    Json(req): Json<NewClassroom>,
) -> Result<(StatusCode, Json<ClassroomView>)> {
    organization_only(&state)?;
    let name = validate_name(&req.name)?;
    let description = validate_description(req.description.as_deref().unwrap_or_default())?;
    let id = Uuid::new_v4();
    // A new code on the (unlikely) collision.
    for _ in 0..5 {
        match cdb::create(
            &state.db,
            id,
            name,
            description,
            teacher.0.id,
            &new_invite_code(),
        )
        .await
        {
            Ok(()) => {
                tracing::info!(teacher = teacher.0.username, name, "classroom created");
                return Ok((StatusCode::CREATED, Json(classroom_view(&state, id).await?)));
            }
            Err(e) if db::violates(&e, "classrooms_invite_code_key") => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Err(ApiError::Internal(anyhow::anyhow!("no free invite code")))
}

/// A classroom with its members and assignments.
#[utoipa::path(get, path = "/api/v1/teach/classrooms/{id}", tag = "teach",
    params(("id" = String, Path, description = "Classroom ID")),
    responses((status = 200, body = ClassroomDetail), (status = 404, body = ErrorBody)))]
async fn get_teaching(
    State(state): State<AppState>,
    teacher: TeacherUser,
    Path(id): Path<String>,
) -> Result<Json<ClassroomDetail>> {
    let c = managed(&state, &teacher, &id).await?;
    let members = cdb::members(&state.db, c.id).await?;
    let assignments = cdb::assignments(&state.db, &[c.id]).await?;
    let challenges = state.cluster.challenges().await?;
    let title = |name: &str| {
        challenges
            .iter()
            .find(|ch| ch.metadata.name.as_deref() == Some(name))
            .and_then(views::package)
            .map(|p| p.spec.title.clone())
    };
    Ok(Json(ClassroomDetail {
        members: members
            .into_iter()
            .map(|m| MemberView {
                id: m.user_id,
                username: m.username,
                display_name: m.display_name,
                joined_at: m.joined_at,
                last_login_at: m.last_login_at,
            })
            .collect(),
        assignments: assignments
            .into_iter()
            .map(|a| AssignmentView {
                title: title(&a.challenge),
                challenge: a.challenge,
                opens_at: a.opens_at,
                due_at: a.due_at,
            })
            .collect(),
        classroom: c.into(),
    }))
}

/// Renames a classroom, turns its invite link on or off, or (admins) gives
/// it to another teacher.
#[utoipa::path(patch, path = "/api/v1/teach/classrooms/{id}", tag = "teach",
    params(("id" = String, Path, description = "Classroom ID")), request_body = ClassroomChange,
    responses((status = 200, body = ClassroomView), (status = 400, body = ErrorBody),
              (status = 403, body = ErrorBody), (status = 404, body = ErrorBody)))]
async fn update_classroom(
    State(state): State<AppState>,
    teacher: TeacherUser,
    Path(id): Path<String>,
    Json(req): Json<ClassroomChange>,
) -> Result<Json<ClassroomView>> {
    let c = managed(&state, &teacher, &id).await?;
    let name = req.name.as_deref().map(validate_name).transpose()?;
    let description = req
        .description
        .as_deref()
        .map(validate_description)
        .transpose()?;
    if let Some(owner) = req.owner_id.filter(|o| *o != c.owner_id) {
        if !teacher.is_admin() {
            return Err(ApiError::Forbidden(
                "only admins can give a classroom to another teacher".into(),
            ));
        }
        let new_owner = db::user_by_id(&state.db, owner)
            .await?
            .ok_or_else(|| ApiError::BadRequest(format!("no user {owner}")))?;
        if new_owner.role == STUDENT_ROLE || new_owner.disabled_at.is_some() {
            return Err(ApiError::BadRequest(
                "a classroom belongs to an enabled teacher or admin".into(),
            ));
        }
    }
    cdb::update(
        &state.db,
        c.id,
        name,
        description,
        req.invite_enabled,
        req.owner_id,
    )
    .await?;
    Ok(Json(classroom_view(&state, c.id).await?))
}

/// Deletes a classroom with its memberships and assignments. Accounts and
/// scores are kept.
#[utoipa::path(delete, path = "/api/v1/teach/classrooms/{id}", tag = "teach",
    params(("id" = String, Path, description = "Classroom ID")),
    responses((status = 204), (status = 404, body = ErrorBody)))]
async fn delete_classroom(
    State(state): State<AppState>,
    teacher: TeacherUser,
    Path(id): Path<String>,
) -> Result<StatusCode> {
    let c = managed(&state, &teacher, &id).await?;
    cdb::delete(&state.db, c.id).await?;
    tracing::info!(
        teacher = teacher.0.username,
        name = c.name,
        "classroom deleted"
    );
    Ok(StatusCode::NO_CONTENT)
}

/// Replaces the invite code: the old link stops working.
#[utoipa::path(post, path = "/api/v1/teach/classrooms/{id}/invite", tag = "teach",
    params(("id" = String, Path, description = "Classroom ID")),
    responses((status = 200, body = ClassroomView), (status = 404, body = ErrorBody)))]
async fn rotate_invite(
    State(state): State<AppState>,
    teacher: TeacherUser,
    Path(id): Path<String>,
) -> Result<Json<ClassroomView>> {
    let c = managed(&state, &teacher, &id).await?;
    for _ in 0..5 {
        match cdb::set_invite_code(&state.db, c.id, &new_invite_code()).await {
            Ok(()) => return Ok(Json(classroom_view(&state, c.id).await?)),
            Err(e) if db::violates(&e, "classrooms_invite_code_key") => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Err(ApiError::Internal(anyhow::anyhow!("no free invite code")))
}

/// Removes a member from a classroom (their account and scores are kept).
#[utoipa::path(delete, path = "/api/v1/teach/classrooms/{id}/members/{user}", tag = "teach",
    params(("id" = String, Path, description = "Classroom ID"),
           ("user" = String, Path, description = "User ID")),
    responses((status = 204), (status = 404, body = ErrorBody)))]
async fn remove_member(
    State(state): State<AppState>,
    teacher: TeacherUser,
    Path((id, user)): Path<(String, String)>,
) -> Result<StatusCode> {
    let c = managed(&state, &teacher, &id).await?;
    let user =
        Uuid::parse_str(&user).map_err(|_| ApiError::NotFound(format!("no member {user}")))?;
    match cdb::remove_member(&state.db, c.id, user).await? {
        true => Ok(StatusCode::NO_CONTENT),
        false => Err(ApiError::NotFound(format!("no member {user}"))),
    }
}

/// Assigns an installed challenge to a classroom, or changes its dates.
#[utoipa::path(put, path = "/api/v1/teach/classrooms/{id}/assignments/{challenge}", tag = "teach",
    params(("id" = String, Path, description = "Classroom ID"),
           ("challenge" = String, Path, description = "Challenge name")),
    request_body = AssignmentDates,
    responses((status = 200, body = AssignmentView), (status = 400, body = ErrorBody),
              (status = 404, body = ErrorBody)))]
async fn put_assignment(
    State(state): State<AppState>,
    teacher: TeacherUser,
    Path((id, challenge)): Path<(String, String)>,
    Json(req): Json<AssignmentDates>,
) -> Result<Json<AssignmentView>> {
    let c = managed(&state, &teacher, &id).await?;
    let ch = state
        .cluster
        .challenge(&challenge)
        .await?
        .filter(|ch| !ch.spec.disabled.unwrap_or(false))
        .ok_or_else(|| ApiError::NotFound(format!("challenge {challenge} is not installed")))?;
    if let (Some(opens), Some(due)) = (req.opens_at, req.due_at)
        && opens >= due
    {
        return Err(ApiError::BadRequest(
            "the deadline must come after the opening date".into(),
        ));
    }
    let a = cdb::put_assignment(&state.db, c.id, &challenge, req.opens_at, req.due_at).await?;
    Ok(Json(AssignmentView {
        title: views::package(&ch).map(|p| p.spec.title.clone()),
        challenge: a.challenge,
        opens_at: a.opens_at,
        due_at: a.due_at,
    }))
}

/// Removes an assignment (solves are kept).
#[utoipa::path(delete, path = "/api/v1/teach/classrooms/{id}/assignments/{challenge}", tag = "teach",
    params(("id" = String, Path, description = "Classroom ID"),
           ("challenge" = String, Path, description = "Challenge name")),
    responses((status = 204), (status = 404, body = ErrorBody)))]
async fn delete_assignment(
    State(state): State<AppState>,
    teacher: TeacherUser,
    Path((id, challenge)): Path<(String, String)>,
) -> Result<StatusCode> {
    let c = managed(&state, &teacher, &id).await?;
    match cdb::delete_assignment(&state.db, c.id, &challenge).await? {
        true => Ok(StatusCode::NO_CONTENT),
        false => Err(ApiError::NotFound(format!("{challenge} is not assigned"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invite_codes() {
        let code = new_invite_code();
        assert_eq!(code.len(), CODE_LENGTH);
        assert!(code.bytes().all(|b| CODE_ALPHABET.contains(&b)));
        assert_ne!(new_invite_code(), new_invite_code());
        assert_eq!(normalize_code(" abcd-efgh "), "ABCDEFGH");
        assert_eq!(display_code("ABCDEFGH"), "ABCD-EFGH");
    }

    #[test]
    fn names() {
        assert_eq!(validate_name("  Class 1A ").unwrap(), "Class 1A");
        assert!(validate_name(" ").is_err());
        assert!(validate_description(&"x".repeat(2001)).is_err());
    }
}
