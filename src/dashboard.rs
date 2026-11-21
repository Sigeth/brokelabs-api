//! The teacher dashboard (M5): progress of a classroom's students on its
//! assignments, CSV export, and resetting or stopping a student's instance.

use std::collections::BTreeMap;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use time::OffsetDateTime;
use utoipa::ToSchema;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use uuid::Uuid;

use crate::app::AppState;
use crate::auth::TeacherUser;
use crate::classrooms::managed;
use crate::db::{self, classrooms as cdb};
use crate::error::{ApiError, ErrorBody};
use crate::views::{self, InstancePhase, InstanceView};

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(progress))
        .routes(routes!(progress_csv))
        .routes(routes!(stop_instance))
        .routes(routes!(reset_instance))
}

type Result<T> = std::result::Result<T, ApiError>;

/// An assignment, as a column of the dashboard.
#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProgressAssignment {
    pub challenge: String,
    /// None when the challenge is no longer installed.
    pub title: Option<String>,
    pub tasks: usize,
    pub points: i64,
    #[serde(with = "time::serde::rfc3339::option")]
    pub opens_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub due_at: Option<OffsetDateTime>,
}

/// Where a student stands on one assignment.
#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProgressCell {
    pub challenge: String,
    pub solved_tasks: usize,
    pub solved_points: i64,
    /// Every task is solved.
    pub done: bool,
    /// A task was solved after the deadline (D58).
    pub late: bool,
    #[serde(with = "time::serde::rfc3339::option")]
    pub last_solved_at: Option<OffsetDateTime>,
}

/// A running instance of a student.
#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RunningInstance {
    pub id: String,
    pub challenge: String,
    pub phase: InstancePhase,
    #[serde(with = "time::serde::rfc3339")]
    pub started_at: OffsetDateTime,
}

/// A row of the dashboard.
#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct StudentProgress {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub email: Option<String>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub last_login_at: Option<OffsetDateTime>,
    /// Points on this classroom's assignments.
    pub points: i64,
    /// One per assignment, in the order of `assignments`.
    pub cells: Vec<ProgressCell>,
    /// Instances running now, whatever their challenge.
    pub instances: Vec<RunningInstance>,
}

/// Progress of a classroom's students on its assignments.
#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ClassroomProgress {
    pub classroom: String,
    pub assignments: Vec<ProgressAssignment>,
    pub students: Vec<StudentProgress>,
}

async fn build(state: &AppState, classroom: &cdb::Classroom) -> Result<ClassroomProgress> {
    let members = cdb::members(&state.db, classroom.id).await?;
    let assigned = cdb::assignments(&state.db, &[classroom.id]).await?;
    let users: Vec<Uuid> = members.iter().map(|m| m.user_id).collect();
    let names: Vec<String> = assigned.iter().map(|a| a.challenge.clone()).collect();
    let solves = cdb::solves_of(&state.db, &users, &names).await?;
    let attempts = cdb::active_attempts_of(&state.db, &users).await?;
    let challenges = state.cluster.challenges().await?;
    let instances: BTreeMap<String, InstancePhase> = state
        .cluster
        .instances()
        .await?
        .iter()
        .map(|ci| {
            let view = views::instance(ci, Vec::new());
            (view.id, view.phase)
        })
        .collect();

    let assignments: Vec<ProgressAssignment> = assigned
        .iter()
        .map(|a| {
            let pkg = challenges
                .iter()
                .find(|c| c.metadata.name.as_deref() == Some(a.challenge.as_str()))
                .and_then(views::package);
            ProgressAssignment {
                challenge: a.challenge.clone(),
                title: pkg.map(|p| p.spec.title.clone()),
                tasks: pkg.map(|p| p.spec.tasks.len()).unwrap_or_default(),
                points: pkg
                    .map(|p| p.spec.tasks.iter().map(|t| i64::from(t.points)).sum())
                    .unwrap_or_default(),
                opens_at: a.opens_at,
                due_at: a.due_at,
            }
        })
        .collect();

    let students = members
        .into_iter()
        .map(|m| {
            let cells: Vec<ProgressCell> = assignments
                .iter()
                .map(|a| {
                    let mine: Vec<&cdb::MemberSolve> = solves
                        .iter()
                        .filter(|s| s.user_id == m.user_id && s.challenge == a.challenge)
                        .collect();
                    ProgressCell {
                        challenge: a.challenge.clone(),
                        solved_tasks: mine.len(),
                        solved_points: mine.iter().map(|s| i64::from(s.points)).sum(),
                        done: a.tasks > 0 && mine.len() >= a.tasks,
                        late: a
                            .due_at
                            .is_some_and(|due| mine.iter().any(|s| s.solved_at > due)),
                        last_solved_at: mine.iter().map(|s| s.solved_at).max(),
                    }
                })
                .collect();
            StudentProgress {
                points: cells.iter().map(|c| c.solved_points).sum(),
                instances: attempts
                    .iter()
                    .filter(|a| a.user_id == m.user_id)
                    .filter_map(|a| {
                        instances
                            .get(&a.instance_name)
                            .map(|phase| RunningInstance {
                                id: a.instance_name.clone(),
                                challenge: a.challenge.clone(),
                                phase: *phase,
                                started_at: a.started_at,
                            })
                    })
                    .collect(),
                cells,
                id: m.user_id,
                username: m.username,
                display_name: m.display_name,
                email: m.email,
                last_login_at: m.last_login_at,
            }
        })
        .collect();
    Ok(ClassroomProgress {
        classroom: classroom.name.clone(),
        assignments,
        students,
    })
}

/// Progress of the classroom's students on its assignments, with their
/// running instances.
#[utoipa::path(get, path = "/api/v1/teach/classrooms/{id}/progress", tag = "teach",
    params(("id" = String, Path, description = "Classroom ID")),
    responses((status = 200, body = ClassroomProgress), (status = 404, body = ErrorBody)))]
async fn progress(
    State(state): State<AppState>,
    teacher: TeacherUser,
    Path(id): Path<String>,
) -> Result<Json<ClassroomProgress>> {
    let c = managed(&state, &teacher, &id).await?;
    Ok(Json(build(&state, &c).await?))
}

/// A CSV field: quoted when needed, and never read as a formula by
/// spreadsheets (names are typed by students).
fn csv_field(value: &str) -> String {
    let value = match value.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        true => format!("'{value}"),
        false => value.to_string(),
    };
    match value.contains([',', '"', '\n', '\r']) {
        true => format!("\"{}\"", value.replace('"', "\"\"")),
        false => value,
    }
}

fn csv_row(fields: &[String]) -> String {
    let mut row = fields
        .iter()
        .map(|f| csv_field(f))
        .collect::<Vec<_>>()
        .join(",");
    row.push_str("\r\n");
    row
}

fn rfc3339(t: Option<OffsetDateTime>) -> String {
    t.and_then(|t| {
        t.format(&time::format_description::well_known::Rfc3339)
            .ok()
    })
    .unwrap_or_default()
}

/// One row per student: totals, then points, tasks, late and last solve per
/// assignment.
fn to_csv(p: &ClassroomProgress) -> String {
    let mut header = vec![
        "username".to_string(),
        "name".to_string(),
        "email".to_string(),
        "last sign-in".to_string(),
        "points".to_string(),
    ];
    for a in &p.assignments {
        let title = a.title.as_deref().unwrap_or(&a.challenge);
        header.push(format!("{title}: points (of {})", a.points));
        header.push(format!("{title}: tasks (of {})", a.tasks));
        header.push(format!("{title}: late"));
        header.push(format!("{title}: last solve"));
    }
    let mut out = csv_row(&header);
    for s in &p.students {
        let mut row = vec![
            s.username.clone(),
            s.display_name.clone(),
            s.email.clone().unwrap_or_default(),
            rfc3339(s.last_login_at),
            s.points.to_string(),
        ];
        for c in &s.cells {
            row.push(c.solved_points.to_string());
            row.push(c.solved_tasks.to_string());
            row.push(if c.late { "yes" } else { "no" }.to_string());
            row.push(rfc3339(c.last_solved_at));
        }
        out.push_str(&csv_row(&row));
    }
    out
}

/// A file name from a classroom name: `class-1a-progress.csv`.
fn file_name(classroom: &str) -> String {
    let slug: String = classroom
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    let slug = slug
        .split('-')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("-");
    match slug.is_empty() {
        true => "progress.csv".into(),
        false => format!("{slug}-progress.csv"),
    }
}

/// The progress as a CSV file (one row per student).
#[utoipa::path(get, path = "/api/v1/teach/classrooms/{id}/progress.csv", tag = "teach",
    params(("id" = String, Path, description = "Classroom ID")),
    responses((status = 200, description = "CSV file", content_type = "text/csv"),
              (status = 404, body = ErrorBody)))]
async fn progress_csv(
    State(state): State<AppState>,
    teacher: TeacherUser,
    Path(id): Path<String>,
) -> Result<Response> {
    let c = managed(&state, &teacher, &id).await?;
    let p = build(&state, &c).await?;
    Ok((
        [
            (header::CONTENT_TYPE, "text/csv; charset=utf-8".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{}\"", file_name(&c.name)),
            ),
        ],
        // A byte order mark, so spreadsheets read UTF-8 names correctly.
        format!("\u{feff}{}", to_csv(&p)),
    )
        .into_response())
}

/// A member's active attempt on a classroom the teacher manages.
async fn member_attempt(
    state: &AppState,
    teacher: &TeacherUser,
    id: &str,
    user: &str,
    instance: &str,
) -> Result<(cdb::Classroom, db::User, db::Attempt)> {
    let c = managed(state, teacher, id).await?;
    let not_found = || ApiError::NotFound(format!("no running instance {instance}"));
    let user = Uuid::parse_str(user).map_err(|_| not_found())?;
    if !cdb::is_member(&state.db, c.id, user).await? {
        return Err(not_found());
    }
    let student = db::user_by_id(&state.db, user)
        .await?
        .ok_or_else(not_found)?;
    let attempt = db::attempt_by_instance(&state.db, instance)
        .await?
        .filter(|a| a.user_id == user && a.ended_at.is_none())
        .ok_or_else(not_found)?;
    Ok((c, student, attempt))
}

/// Stops a student's instance: everything in it is lost, the score is kept.
#[utoipa::path(delete, path = "/api/v1/teach/classrooms/{id}/members/{user}/instances/{instance}", tag = "teach",
    params(("id" = String, Path, description = "Classroom ID"),
           ("user" = String, Path, description = "User ID"),
           ("instance" = String, Path, description = "Instance ID")),
    responses((status = 204), (status = 404, body = ErrorBody)))]
async fn stop_instance(
    State(state): State<AppState>,
    teacher: TeacherUser,
    Path((id, user, instance)): Path<(String, String, String)>,
) -> Result<StatusCode> {
    let (c, student, attempt) = member_attempt(&state, &teacher, &id, &user, &instance).await?;
    state
        .cluster
        .delete_instance(&attempt.instance_name)
        .await?;
    db::end_attempt(&state.db, &attempt.instance_name, "stopped by a teacher").await?;
    tracing::info!(
        teacher = teacher.0.username,
        student = student.username,
        classroom = c.name,
        instance,
        "instance stopped by a teacher"
    );
    Ok(StatusCode::NO_CONTENT)
}

/// Resets a student's instance: stops it and starts a fresh one of the same
/// challenge for them. The score is kept.
#[utoipa::path(post, path = "/api/v1/teach/classrooms/{id}/members/{user}/instances/{instance}/reset", tag = "teach",
    params(("id" = String, Path, description = "Classroom ID"),
           ("user" = String, Path, description = "User ID"),
           ("instance" = String, Path, description = "Instance ID")),
    responses((status = 201, body = InstanceView), (status = 404, body = ErrorBody),
              (status = 409, body = ErrorBody)))]
async fn reset_instance(
    State(state): State<AppState>,
    teacher: TeacherUser,
    Path((id, user, instance)): Path<(String, String, String)>,
) -> Result<(StatusCode, Json<InstanceView>)> {
    let (c, student, attempt) = member_attempt(&state, &teacher, &id, &user, &instance).await?;
    if student.disabled_at.is_some() {
        return Err(ApiError::Conflict(
            "the student's account is disabled".into(),
        ));
    }
    state
        .cluster
        .delete_instance(&attempt.instance_name)
        .await?;
    db::end_attempt(&state.db, &attempt.instance_name, "reset by a teacher").await?;
    let fresh = crate::routes::start_for(&state, &student, &attempt.challenge).await?;
    tracing::info!(
        teacher = teacher.0.username,
        student = student.username,
        classroom = c.name,
        old = instance,
        new = fresh.id,
        "instance reset by a teacher"
    );
    Ok((StatusCode::CREATED, Json(fresh)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_fields_are_quoted_and_never_formulas() {
        assert_eq!(csv_field("Sam"), "Sam");
        assert_eq!(csv_field("Smith, Sam"), "\"Smith, Sam\"");
        assert_eq!(csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_field("=HYPERLINK(\"x\")"), "\"'=HYPERLINK(\"\"x\"\")\"");
        assert_eq!(csv_field("+1"), "'+1");
        assert_eq!(csv_field("@SUM(A1)"), "'@SUM(A1)");
    }

    #[test]
    fn file_names() {
        assert_eq!(file_name("Class 1A"), "class-1a-progress.csv");
        assert_eq!(file_name("  DevOps / 2026 "), "devops-2026-progress.csv");
        assert_eq!(file_name("éé"), "progress.csv");
    }

    #[test]
    fn csv_export() {
        let p = ClassroomProgress {
            classroom: "C".into(),
            assignments: vec![ProgressAssignment {
                challenge: "hello".into(),
                title: Some("Hello".into()),
                tasks: 2,
                points: 15,
                opens_at: None,
                due_at: None,
            }],
            students: vec![StudentProgress {
                id: Uuid::nil(),
                username: "sam".into(),
                display_name: "=cmd".into(),
                email: None,
                last_login_at: None,
                points: 10,
                cells: vec![ProgressCell {
                    challenge: "hello".into(),
                    solved_tasks: 1,
                    solved_points: 10,
                    done: false,
                    late: true,
                    last_solved_at: None,
                }],
                instances: vec![],
            }],
        };
        let csv = to_csv(&p);
        let lines: Vec<&str> = csv.split("\r\n").collect();
        assert_eq!(
            lines[0],
            "username,name,email,last sign-in,points,Hello: points (of 15),Hello: tasks (of 2),Hello: late,Hello: last solve"
        );
        assert_eq!(lines[1], "sam,'=cmd,,,10,10,1,yes,");
    }
}
