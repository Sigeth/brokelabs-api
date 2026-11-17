//! Shapes returned by the API (and to the web UI through the OpenAPI document).

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use brokelabs_types::Challenge;
use brokelabs_types::generated::challenges::ChallengeStatusPackage;
use brokelabs_types::{
    ChallengeInstance, generated::challengeinstances::ChallengeInstanceStatusPhase,
};

use crate::db;

/// The signed-in user.
#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct Me {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    /// admin, teacher or student.
    pub role: String,
    /// Points of every solved task.
    pub score: i64,
}

#[derive(Deserialize, ToSchema)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

/// A challenge in the catalog.
#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ChallengeSummary {
    pub name: String,
    pub version: String,
    pub title: String,
    pub summary: String,
    /// linux-hardening, containers or kubernetes.
    pub category: String,
    /// easy, medium, hard or insane.
    pub difficulty: String,
    /// Typical time to solve, in minutes.
    pub estimated_minutes: Option<i64>,
    pub tags: Vec<String>,
    /// Points of all tasks.
    pub points: i64,
    /// Points the user has already scored.
    pub solved_points: i64,
    pub tasks: usize,
    pub solved_tasks: usize,
    /// False when this cluster cannot run the challenge.
    pub runnable: bool,
    pub unrunnable_reason: Option<String>,
}

/// A gradable objective.
#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TaskView {
    pub id: String,
    pub title: String,
    pub points: i32,
    pub solved: bool,
}

/// A terminal offered on a machine.
#[derive(Clone, Serialize, ToSchema)]
pub struct TerminalView {
    pub machine: String,
    pub label: String,
}

/// A challenge with its instructions and tasks.
#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ChallengeDetail {
    #[serde(flatten)]
    pub summary: ChallengeSummary,
    /// Student instructions, in markdown.
    pub instructions: Option<String>,
    pub task_list: Vec<TaskView>,
    pub terminals: Vec<TerminalView>,
}

/// Lifecycle phase of an instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub enum InstancePhase {
    Queued,
    Provisioning,
    Ready,
    Expired,
    Failed,
    /// Being deleted after a stop.
    Stopping,
}

/// A running attempt of the user.
#[derive(Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct InstanceView {
    /// Instance name, used in /instances/{id} paths.
    pub id: String,
    pub challenge: String,
    pub phase: InstancePhase,
    /// Why the instance is in its phase (progress, failure reason...).
    pub message: Option<String>,
    #[serde(with = "time::serde::rfc3339::option")]
    #[schema(value_type = Option<String>, format = DateTime)]
    pub expires_at: Option<OffsetDateTime>,
    pub terminals: Vec<TerminalView>,
}

#[derive(Deserialize, ToSchema)]
pub struct StartInstance {
    /// Name of the challenge.
    pub challenge: String,
}

#[derive(Deserialize, ToSchema)]
pub struct OpenTerminal {
    /// Machine of one of the challenge's terminals.
    pub machine: String,
}

/// Where the browser opens a terminal.
#[derive(Serialize, ToSchema)]
pub struct TerminalAccess {
    /// WebSocket URL of the gateway, with a short-lived token.
    pub url: String,
}

/// Lifecycle phase of a check run.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub enum CheckPhase {
    Pending,
    Running,
    Completed,
    Error,
}

/// Result of checking one task.
#[derive(Clone, Serialize, ToSchema)]
pub struct TaskResultView {
    pub task: String,
    pub passed: bool,
    pub message: Option<String>,
}

/// A validation of an instance.
#[derive(Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CheckRunView {
    pub id: String,
    pub instance: String,
    pub phase: CheckPhase,
    /// Explains an Error phase.
    pub message: Option<String>,
    pub results: Vec<TaskResultView>,
    /// Tasks this run solved for the first time.
    pub newly_solved: Vec<String>,
}

/// Pushed on GET /api/v1/events (server-sent events, one JSON object per message).
#[derive(Clone, Serialize, ToSchema)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum Event {
    /// An instance of the user changed.
    Instance { instance: InstanceView },
    /// An instance of the user is gone.
    InstanceDeleted { id: String },
    /// A check run of the user changed.
    Check { check: CheckRunView },
}

/// The package of an installed challenge, when the operator resolved it.
pub fn package(ch: &Challenge) -> Option<&ChallengeStatusPackage> {
    ch.status.as_ref().and_then(|s| s.package.as_ref())
}

fn enum_str<T: Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

/// Parses a Go duration ("1h30m0s", "45m") into minutes.
fn minutes(go_duration: &str) -> Option<i64> {
    let (mut total, mut num) = (0f64, String::new());
    let mut chars = go_duration.chars().peekable();
    while let Some(c) = chars.next() {
        if c.is_ascii_digit() || c == '.' {
            num.push(c);
            continue;
        }
        let value: f64 = num.parse().ok()?;
        num.clear();
        total += match c {
            'h' => value * 60.0,
            'm' if chars.peek() == Some(&'s') => {
                chars.next();
                value / 60_000.0
            }
            'm' => value,
            's' => value / 60.0,
            _ => return None,
        };
    }
    num.is_empty().then_some(total.round() as i64)
}

pub fn summary(ch: &Challenge, solves: &[db::Solve]) -> Option<ChallengeSummary> {
    let pkg = package(ch)?;
    let name = ch.metadata.name.clone()?;
    let spec = &pkg.spec;
    let solved: Vec<&db::Solve> = solves.iter().filter(|s| s.challenge == name).collect();
    let status = ch.status.as_ref();
    Some(ChallengeSummary {
        version: pkg.metadata.version.clone(),
        title: spec.title.clone(),
        summary: spec.summary.clone(),
        category: enum_str(&spec.category),
        difficulty: enum_str(&spec.difficulty),
        estimated_minutes: spec.estimated_time.as_deref().and_then(minutes),
        tags: spec.tags.clone().unwrap_or_default(),
        points: spec.tasks.iter().map(|t| i64::from(t.points)).sum(),
        solved_points: solved.iter().map(|s| i64::from(s.points)).sum(),
        tasks: spec.tasks.len(),
        solved_tasks: solved.len(),
        runnable: status.and_then(|s| s.runnable).unwrap_or(false),
        unrunnable_reason: status
            .and_then(|s| s.unrunnable_reason.clone())
            .filter(|r| !r.is_empty()),
        name,
    })
}

pub fn terminals(pkg: &ChallengeStatusPackage) -> Vec<TerminalView> {
    pkg.spec
        .access
        .terminals
        .iter()
        .map(|t| TerminalView {
            machine: t.machine.clone(),
            label: t.label.clone().unwrap_or_else(|| t.machine.clone()),
        })
        .collect()
}

pub fn tasks(pkg: &ChallengeStatusPackage, challenge: &str, solves: &[db::Solve]) -> Vec<TaskView> {
    pkg.spec
        .tasks
        .iter()
        .map(|t| TaskView {
            id: t.id.clone(),
            title: t.title.clone(),
            points: t.points,
            solved: solves
                .iter()
                .any(|s| s.challenge == challenge && s.task == t.id),
        })
        .collect()
}

pub fn instance(ci: &ChallengeInstance, terminals: Vec<TerminalView>) -> InstanceView {
    let status = ci.status.as_ref();
    let phase = if ci.metadata.deletion_timestamp.is_some() {
        InstancePhase::Stopping
    } else {
        match status.and_then(|s| s.phase.as_ref()) {
            None | Some(ChallengeInstanceStatusPhase::Queued) => InstancePhase::Queued,
            Some(ChallengeInstanceStatusPhase::Provisioning) => InstancePhase::Provisioning,
            Some(ChallengeInstanceStatusPhase::Ready) => InstancePhase::Ready,
            Some(ChallengeInstanceStatusPhase::Expired) => InstancePhase::Expired,
            Some(ChallengeInstanceStatusPhase::Failed) => InstancePhase::Failed,
        }
    };
    InstanceView {
        id: ci.metadata.name.clone().unwrap_or_default(),
        challenge: ci.spec.challenge.clone(),
        phase,
        message: status
            .and_then(|s| s.message.clone())
            .filter(|m| !m.is_empty()),
        expires_at: status.and_then(|s| s.expires_at.as_ref()).and_then(|t| {
            OffsetDateTime::parse(t, &time::format_description::well_known::Rfc3339).ok()
        }),
        terminals,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn go_durations() {
        assert_eq!(minutes("30m0s"), Some(30));
        assert_eq!(minutes("1h30m0s"), Some(90));
        assert_eq!(minutes("90s"), Some(2));
        assert_eq!(minutes("1.5h"), Some(90));
        assert_eq!(minutes("500ms"), Some(0));
        assert_eq!(minutes("soon"), None);
    }
}
