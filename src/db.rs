//! PostgreSQL store: users, sessions, attempts, check runs and scores.

use sqlx::AssertSqlSafe;
use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::types::Json;
use time::OffsetDateTime;
use uuid::Uuid;

pub type Result<T> = std::result::Result<T, sqlx::Error>;

/// Connects and applies the migrations.
pub async fn connect(url: &str) -> anyhow::Result<PgPool> {
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(url)
        .await?;
    sqlx::migrate!().run(&pool).await?;
    Ok(pool)
}

#[derive(Clone, Debug, sqlx::FromRow)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub role: String,
    pub password_hash: Option<String>,
}

pub async fn count_users(db: &PgPool) -> Result<i64> {
    sqlx::query_scalar("SELECT count(*) FROM users")
        .fetch_one(db)
        .await
}

pub async fn user_by_name(db: &PgPool, username: &str) -> Result<Option<User>> {
    sqlx::query_as(
        "SELECT id, username, display_name, role, password_hash FROM users WHERE username = $1",
    )
    .bind(username)
    .fetch_optional(db)
    .await
}

pub async fn create_user(
    db: &PgPool,
    username: &str,
    display_name: &str,
    role: &str,
    password_hash: &str,
) -> Result<User> {
    sqlx::query_as(
        "INSERT INTO users (id, username, display_name, role, password_hash) VALUES ($1, $2, $3, $4, $5)
         RETURNING id, username, display_name, role, password_hash",
    )
    .bind(Uuid::new_v4())
    .bind(username)
    .bind(display_name)
    .bind(role)
    .bind(password_hash)
    .fetch_one(db)
    .await
}

pub async fn set_password(db: &PgPool, user: Uuid, password_hash: &str) -> Result<()> {
    sqlx::query("UPDATE users SET password_hash = $2 WHERE id = $1")
        .bind(user)
        .bind(password_hash)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn create_session(
    db: &PgPool,
    token_hash: &[u8],
    user: Uuid,
    expires_at: OffsetDateTime,
) -> Result<()> {
    sqlx::query("INSERT INTO sessions (token_hash, user_id, expires_at) VALUES ($1, $2, $3)")
        .bind(token_hash)
        .bind(user)
        .bind(expires_at)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn session_user(db: &PgPool, token_hash: &[u8]) -> Result<Option<User>> {
    sqlx::query_as(
        "SELECT u.id, u.username, u.display_name, u.role, u.password_hash
         FROM sessions s JOIN users u ON u.id = s.user_id
         WHERE s.token_hash = $1 AND s.expires_at > now()",
    )
    .bind(token_hash)
    .fetch_optional(db)
    .await
}

pub async fn delete_session(db: &PgPool, token_hash: &[u8]) -> Result<()> {
    sqlx::query("DELETE FROM sessions WHERE token_hash = $1 OR expires_at < now()")
        .bind(token_hash)
        .execute(db)
        .await?;
    Ok(())
}

#[derive(Clone, Debug, sqlx::FromRow)]
pub struct Attempt {
    pub id: Uuid,
    pub user_id: Uuid,
    pub challenge: String,
    pub instance_name: String,
    pub ended_at: Option<OffsetDateTime>,
}

const ATTEMPT_COLUMNS: &str = "id, user_id, challenge, instance_name, ended_at";

/// Records a new attempt. Fails with a unique violation when the user already
/// has an active one.
pub async fn create_attempt(
    db: &PgPool,
    id: Uuid,
    user: Uuid,
    challenge: &str,
    version: &str,
    instance_name: &str,
) -> Result<Attempt> {
    sqlx::query_as(AssertSqlSafe(format!(
        "INSERT INTO attempts (id, user_id, challenge, challenge_version, instance_name)
         VALUES ($1, $2, $3, $4, $5) RETURNING {ATTEMPT_COLUMNS}"
    )))
    .bind(id)
    .bind(user)
    .bind(challenge)
    .bind(version)
    .bind(instance_name)
    .fetch_one(db)
    .await
}

pub async fn delete_attempt(db: &PgPool, id: Uuid) -> Result<()> {
    sqlx::query("DELETE FROM attempts WHERE id = $1")
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn attempt_by_instance(db: &PgPool, instance_name: &str) -> Result<Option<Attempt>> {
    sqlx::query_as(AssertSqlSafe(format!(
        "SELECT {ATTEMPT_COLUMNS} FROM attempts WHERE instance_name = $1"
    )))
    .bind(instance_name)
    .fetch_optional(db)
    .await
}

pub async fn active_attempts(db: &PgPool, user: Uuid) -> Result<Vec<Attempt>> {
    sqlx::query_as(AssertSqlSafe(format!(
        "SELECT {ATTEMPT_COLUMNS} FROM attempts WHERE user_id = $1 AND ended_at IS NULL ORDER BY started_at"
    )))
    .bind(user)
    .fetch_all(db)
    .await
}

/// Marks an attempt as ended (idempotent: the first reason wins).
pub async fn end_attempt(db: &PgPool, instance_name: &str, reason: &str) -> Result<()> {
    sqlx::query(
        "UPDATE attempts SET ended_at = now(), end_reason = $2 WHERE instance_name = $1 AND ended_at IS NULL",
    )
    .bind(instance_name)
    .bind(reason)
    .execute(db)
    .await?;
    Ok(())
}

/// Result of one task in a check run, stored as JSON.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct TaskResult {
    pub task: String,
    pub passed: bool,
    pub message: Option<String>,
}

#[derive(Clone, Debug, sqlx::FromRow)]
pub struct CheckRun {
    pub id: Uuid,
    pub name: String,
    pub phase: String,
    pub message: Option<String>,
    pub results: Option<Json<Vec<TaskResult>>>,
    pub requested_at: OffsetDateTime,
}

const CHECK_RUN_COLUMNS: &str = "id, name, phase, message, results, requested_at";

pub async fn create_check_run(db: &PgPool, attempt: Uuid, name: &str) -> Result<CheckRun> {
    sqlx::query_as(AssertSqlSafe(format!(
        "INSERT INTO check_runs (id, attempt_id, name) VALUES ($1, $2, $3) RETURNING {CHECK_RUN_COLUMNS}"
    )))
    .bind(Uuid::new_v4())
    .bind(attempt)
    .bind(name)
    .fetch_one(db)
    .await
}

pub async fn delete_check_run(db: &PgPool, id: Uuid) -> Result<()> {
    sqlx::query("DELETE FROM check_runs WHERE id = $1")
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

/// The latest check run of an attempt.
pub async fn latest_check_run(db: &PgPool, attempt: Uuid) -> Result<Option<CheckRun>> {
    sqlx::query_as(AssertSqlSafe(format!(
        "SELECT {CHECK_RUN_COLUMNS} FROM check_runs WHERE attempt_id = $1 ORDER BY requested_at DESC LIMIT 1"
    )))
    .bind(attempt)
    .fetch_optional(db)
    .await
}

pub async fn count_check_runs(db: &PgPool, attempt: Uuid) -> Result<i64> {
    sqlx::query_scalar("SELECT count(*) FROM check_runs WHERE attempt_id = $1")
        .bind(attempt)
        .fetch_one(db)
        .await
}

/// Points of the tasks a check run may solve.
pub struct TaskPoints<'a> {
    pub task: &'a str,
    pub points: i32,
}

/// Records the outcome of a check run and the tasks it solved, once:
/// replaying it (watch restarts, several api replicas) changes nothing.
/// Returns the attempt and the newly solved tasks.
pub async fn complete_check_run(
    db: &PgPool,
    name: &str,
    phase: &str,
    message: Option<&str>,
    results: &[TaskResult],
    points: &[TaskPoints<'_>],
) -> Result<Option<(Attempt, Vec<String>)>> {
    let mut tx = db.begin().await?;
    let run: Option<(Uuid, Uuid)> = sqlx::query_as(
        "UPDATE check_runs SET phase = $2, message = $3, results = $4, completed_at = now()
         WHERE name = $1 AND completed_at IS NULL RETURNING id, attempt_id",
    )
    .bind(name)
    .bind(phase)
    .bind(message)
    .bind(Json(results))
    .fetch_optional(&mut *tx)
    .await?;
    let Some((run_id, attempt_id)) = run else {
        return Ok(None);
    };
    let attempt: Attempt = sqlx::query_as(AssertSqlSafe(format!(
        "SELECT {ATTEMPT_COLUMNS} FROM attempts WHERE id = $1"
    )))
    .bind(attempt_id)
    .fetch_one(&mut *tx)
    .await?;
    let mut solved = Vec::new();
    for r in results.iter().filter(|r| r.passed) {
        let Some(p) = points.iter().find(|p| p.task == r.task) else {
            continue;
        };
        let inserted = sqlx::query(
            "INSERT INTO solves (user_id, challenge, task, points, check_run_id) VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT DO NOTHING",
        )
        .bind(attempt.user_id)
        .bind(&attempt.challenge)
        .bind(&r.task)
        .bind(p.points)
        .bind(run_id)
        .execute(&mut *tx)
        .await?;
        if inserted.rows_affected() == 1 {
            solved.push(r.task.clone());
        }
    }
    tx.commit().await?;
    Ok(Some((attempt, solved)))
}

/// Tasks solved by a user, by challenge.
#[derive(Clone, Debug, sqlx::FromRow)]
pub struct Solve {
    pub challenge: String,
    pub task: String,
    pub points: i32,
}

pub async fn solves(db: &PgPool, user: Uuid) -> Result<Vec<Solve>> {
    sqlx::query_as("SELECT challenge, task, points FROM solves WHERE user_id = $1")
        .bind(user)
        .fetch_all(db)
        .await
}

pub async fn score(db: &PgPool, user: Uuid) -> Result<i64> {
    sqlx::query_scalar("SELECT coalesce(sum(points), 0)::bigint FROM solves WHERE user_id = $1")
        .bind(user)
        .fetch_one(db)
        .await
}

/// True when the error is a unique constraint violation.
pub fn is_unique_violation(err: &sqlx::Error) -> bool {
    matches!(err, sqlx::Error::Database(e) if e.is_unique_violation())
}

#[cfg(test)]
pub mod testing {
    //! Tests needing PostgreSQL run when `BROKELABS_TEST_DATABASE_URL` is set
    //! (the workspace pipeline starts a database), and are skipped otherwise.

    use sqlx::postgres::{PgPool, PgPoolOptions};
    use sqlx::{AssertSqlSafe, Executor};

    /// A fresh, migrated database, or None when no test database is configured.
    pub async fn database() -> Option<PgPool> {
        let Ok(url) = std::env::var("BROKELABS_TEST_DATABASE_URL") else {
            eprintln!("BROKELABS_TEST_DATABASE_URL is not set: skipping a database test");
            return None;
        };
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .unwrap();
        let name = format!("test_{}", uuid::Uuid::new_v4().simple());
        admin
            .execute(AssertSqlSafe(format!("CREATE DATABASE {name}")))
            .await
            .unwrap();
        let (base, _) = url.rsplit_once('/').unwrap();
        Some(super::connect(&format!("{base}/{name}")).await.unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn check_runs_are_recorded_once() {
        let Some(db) = testing::database().await else {
            return;
        };
        let user = create_user(&db, "alice", "Alice", "student", "x")
            .await
            .unwrap();
        let attempt = create_attempt(&db, Uuid::new_v4(), user.id, "hello", "0.1.0", "hello-1")
            .await
            .unwrap();
        create_check_run(&db, attempt.id, "hello-1-1")
            .await
            .unwrap();
        let results = vec![
            TaskResult {
                task: "a".into(),
                passed: true,
                message: None,
            },
            TaskResult {
                task: "b".into(),
                passed: false,
                message: Some("no".into()),
            },
        ];
        let points = [
            TaskPoints {
                task: "a",
                points: 10,
            },
            TaskPoints {
                task: "b",
                points: 5,
            },
        ];

        let (_, solved) =
            complete_check_run(&db, "hello-1-1", "Completed", None, &results, &points)
                .await
                .unwrap()
                .unwrap();
        assert_eq!(solved, ["a"]);
        // A replay is ignored.
        assert!(
            complete_check_run(&db, "hello-1-1", "Completed", None, &results, &points)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(score(&db, user.id).await.unwrap(), 10);

        // Solving the same task again does not score twice.
        create_check_run(&db, attempt.id, "hello-1-2")
            .await
            .unwrap();
        let (_, solved) =
            complete_check_run(&db, "hello-1-2", "Completed", None, &results, &points)
                .await
                .unwrap()
                .unwrap();
        assert!(solved.is_empty());
        assert_eq!(score(&db, user.id).await.unwrap(), 10);
        let latest = latest_check_run(&db, attempt.id).await.unwrap().unwrap();
        assert_eq!(latest.name, "hello-1-2");
        assert_eq!(latest.results.unwrap().0, results);
    }

    #[tokio::test]
    async fn one_active_attempt_per_user() {
        let Some(db) = testing::database().await else {
            return;
        };
        let user = create_user(&db, "bob", "Bob", "student", "x")
            .await
            .unwrap();
        create_attempt(&db, Uuid::new_v4(), user.id, "a", "1.0.0", "a-1")
            .await
            .unwrap();
        let err = create_attempt(&db, Uuid::new_v4(), user.id, "b", "1.0.0", "b-1")
            .await
            .unwrap_err();
        assert!(is_unique_violation(&err));
        end_attempt(&db, "a-1", "stopped").await.unwrap();
        create_attempt(&db, Uuid::new_v4(), user.id, "b", "1.0.0", "b-1")
            .await
            .unwrap();
        assert_eq!(active_attempts(&db, user.id).await.unwrap().len(), 1);
    }
}
