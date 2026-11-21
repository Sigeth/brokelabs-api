//! Classrooms, their members and assignments.

use sqlx::AssertSqlSafe;
use sqlx::postgres::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use super::Result;

#[derive(Clone, Debug, sqlx::FromRow)]
pub struct Classroom {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub owner_id: Uuid,
    pub owner_name: String,
    pub invite_code: String,
    pub invite_enabled: bool,
    pub created_at: OffsetDateTime,
    pub members: i64,
    pub assignments: i64,
}

const CLASSROOM_SELECT: &str =
    "SELECT c.id, c.name, c.description, c.owner_id, u.display_name AS owner_name,
        c.invite_code, c.invite_enabled, c.created_at,
        (SELECT count(*) FROM classroom_members m WHERE m.classroom_id = c.id) AS members,
        (SELECT count(*) FROM assignments a WHERE a.classroom_id = c.id) AS assignments
     FROM classrooms c JOIN users u ON u.id = c.owner_id";

/// Classrooms owned by a user, or every classroom when `owner` is None.
pub async fn list(db: &PgPool, owner: Option<Uuid>) -> Result<Vec<Classroom>> {
    sqlx::query_as(AssertSqlSafe(format!(
        "{CLASSROOM_SELECT} WHERE $1::uuid IS NULL OR c.owner_id = $1 ORDER BY c.name"
    )))
    .bind(owner)
    .fetch_all(db)
    .await
}

/// Classrooms a user has joined.
pub async fn joined(db: &PgPool, user: Uuid) -> Result<Vec<Classroom>> {
    sqlx::query_as(AssertSqlSafe(format!(
        "{CLASSROOM_SELECT} WHERE c.id IN (SELECT classroom_id FROM classroom_members WHERE user_id = $1)
         ORDER BY c.name"
    )))
    .bind(user)
    .fetch_all(db)
    .await
}

pub async fn get(db: &PgPool, id: Uuid) -> Result<Option<Classroom>> {
    sqlx::query_as(AssertSqlSafe(format!("{CLASSROOM_SELECT} WHERE c.id = $1")))
        .bind(id)
        .fetch_optional(db)
        .await
}

pub async fn by_invite_code(db: &PgPool, code: &str) -> Result<Option<Classroom>> {
    sqlx::query_as(AssertSqlSafe(format!(
        "{CLASSROOM_SELECT} WHERE c.invite_code = $1"
    )))
    .bind(code)
    .fetch_optional(db)
    .await
}

pub async fn create(
    db: &PgPool,
    id: Uuid,
    name: &str,
    description: &str,
    owner: Uuid,
    invite_code: &str,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO classrooms (id, name, description, owner_id, invite_code) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(id)
    .bind(name)
    .bind(description)
    .bind(owner)
    .bind(invite_code)
    .execute(db)
    .await?;
    Ok(())
}

/// Changes the given fields; None leaves a field as it is.
pub async fn update(
    db: &PgPool,
    id: Uuid,
    name: Option<&str>,
    description: Option<&str>,
    invite_enabled: Option<bool>,
    owner: Option<Uuid>,
) -> Result<()> {
    sqlx::query(
        "UPDATE classrooms SET name = coalesce($2, name), description = coalesce($3, description),
            invite_enabled = coalesce($4, invite_enabled), owner_id = coalesce($5, owner_id)
         WHERE id = $1",
    )
    .bind(id)
    .bind(name)
    .bind(description)
    .bind(invite_enabled)
    .bind(owner)
    .execute(db)
    .await?;
    Ok(())
}

pub async fn set_invite_code(db: &PgPool, id: Uuid, code: &str) -> Result<()> {
    sqlx::query("UPDATE classrooms SET invite_code = $2 WHERE id = $1")
        .bind(id)
        .bind(code)
        .execute(db)
        .await?;
    Ok(())
}

/// Deletes a classroom with its members and assignments (scores are kept).
pub async fn delete(db: &PgPool, id: Uuid) -> Result<()> {
    sqlx::query("DELETE FROM classrooms WHERE id = $1")
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

/// Adds a member; true when they were not one already.
pub async fn add_member(db: &PgPool, classroom: Uuid, user: Uuid) -> Result<bool> {
    let done = sqlx::query(
        "INSERT INTO classroom_members (classroom_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
    )
    .bind(classroom)
    .bind(user)
    .execute(db)
    .await?;
    Ok(done.rows_affected() == 1)
}

pub async fn remove_member(db: &PgPool, classroom: Uuid, user: Uuid) -> Result<bool> {
    let done =
        sqlx::query("DELETE FROM classroom_members WHERE classroom_id = $1 AND user_id = $2")
            .bind(classroom)
            .bind(user)
            .execute(db)
            .await?;
    Ok(done.rows_affected() == 1)
}

#[derive(Clone, Debug, sqlx::FromRow)]
pub struct Member {
    pub user_id: Uuid,
    pub username: String,
    pub display_name: String,
    pub joined_at: OffsetDateTime,
    pub last_login_at: Option<OffsetDateTime>,
}

pub async fn members(db: &PgPool, classroom: Uuid) -> Result<Vec<Member>> {
    sqlx::query_as(
        "SELECT u.id AS user_id, u.username, u.display_name, m.joined_at, u.last_login_at
         FROM classroom_members m JOIN users u ON u.id = m.user_id
         WHERE m.classroom_id = $1 ORDER BY u.display_name, u.username",
    )
    .bind(classroom)
    .fetch_all(db)
    .await
}

#[derive(Clone, Debug, sqlx::FromRow)]
pub struct Assignment {
    pub classroom_id: Uuid,
    pub challenge: String,
    pub opens_at: Option<OffsetDateTime>,
    pub due_at: Option<OffsetDateTime>,
}

const ASSIGNMENT_COLUMNS: &str = "classroom_id, challenge, opens_at, due_at";

/// Assignments of classrooms, soonest deadline first.
pub async fn assignments(db: &PgPool, classrooms: &[Uuid]) -> Result<Vec<Assignment>> {
    sqlx::query_as(AssertSqlSafe(format!(
        "SELECT {ASSIGNMENT_COLUMNS} FROM assignments WHERE classroom_id = ANY($1)
         ORDER BY due_at NULLS LAST, created_at"
    )))
    .bind(classrooms)
    .fetch_all(db)
    .await
}

/// Assigns a challenge, or changes its dates when it is assigned already.
pub async fn put_assignment(
    db: &PgPool,
    classroom: Uuid,
    challenge: &str,
    opens_at: Option<OffsetDateTime>,
    due_at: Option<OffsetDateTime>,
) -> Result<Assignment> {
    sqlx::query_as(AssertSqlSafe(format!(
        "INSERT INTO assignments (id, classroom_id, challenge, opens_at, due_at) VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (classroom_id, challenge) DO UPDATE SET opens_at = $4, due_at = $5
         RETURNING {ASSIGNMENT_COLUMNS}"
    )))
    .bind(Uuid::new_v4())
    .bind(classroom)
    .bind(challenge)
    .bind(opens_at)
    .bind(due_at)
    .fetch_one(db)
    .await
}

pub async fn delete_assignment(db: &PgPool, classroom: Uuid, challenge: &str) -> Result<bool> {
    let done = sqlx::query("DELETE FROM assignments WHERE classroom_id = $1 AND challenge = $2")
        .bind(classroom)
        .bind(challenge)
        .execute(db)
        .await?;
    Ok(done.rows_affected() == 1)
}
