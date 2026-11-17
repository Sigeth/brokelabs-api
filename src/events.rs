//! Live updates: watches instances and check runs, records results, and
//! pushes events to the browsers of their owners (server-sent events).
//!
//! Every api replica watches the cluster itself, so each one can push events
//! to its own clients. Recording a check is idempotent, so replicas do not
//! score twice.

use std::convert::Infallible;
use std::time::Duration;

use axum::extract::State;
use axum::response::sse::{self, KeepAlive, Sse};
use brokelabs_types::generated::challengeinstances::ChallengeInstanceStatusPhase;
use brokelabs_types::generated::checkruns::CheckRunStatusPhase;
use brokelabs_types::{ChallengeInstance, CheckRun};
use futures::{Stream, StreamExt, TryStreamExt};
use kube::runtime::{WatchStreamExt, watcher};
use kube::{Api, Client};
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use uuid::Uuid;

use crate::app::AppState;
use crate::auth::CurrentUser;
use crate::db;
use crate::routes::{check_view, instance_view};
use crate::views::{self, Event};

/// Fans events out to the connected browsers.
#[derive(Clone)]
pub struct Hub {
    tx: broadcast::Sender<(Uuid, Event)>,
}

impl Default for Hub {
    fn default() -> Self {
        Self {
            tx: broadcast::channel(256).0,
        }
    }
}

impl Hub {
    pub fn publish(&self, user: Uuid, event: Event) {
        // No receiver is fine: nobody is connected.
        let _ = self.tx.send((user, event));
    }

    pub fn subscribe(&self, user: Uuid) -> impl Stream<Item = Event> + use<> {
        BroadcastStream::new(self.tx.subscribe()).filter_map(move |msg| async move {
            match msg {
                Ok((to, event)) if to == user => Some(event),
                _ => None,
            }
        })
    }
}

/// Server-sent events of the signed-in user (instances and checks). See the
/// `Event` schema.
#[utoipa::path(get, path = "/api/v1/events", tag = "events",
    responses((status = 200, description = "text/event-stream of Event JSON objects", content_type = "text/event-stream")))]
pub async fn events(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
) -> Sse<impl Stream<Item = Result<sse::Event, Infallible>>> {
    let stream = state.hub.subscribe(user.id).map(|event| {
        Ok(sse::Event::default()
            .json_data(&event)
            .unwrap_or_else(|_| sse::Event::default()))
    });
    Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(20)))
}

/// Watches instances and check runs until the process stops.
pub async fn watch(state: AppState, client: Client) {
    let ns = state.config.instances_namespace.clone();
    tokio::join!(
        watch_instances(state.clone(), Api::namespaced(client.clone(), &ns)),
        watch_check_runs(state, Api::namespaced(client, &ns)),
    );
}

async fn watch_instances(state: AppState, api: Api<ChallengeInstance>) {
    let mut stream = watcher(api, watcher::Config::default())
        .default_backoff()
        .boxed();
    loop {
        match stream.try_next().await {
            Ok(Some(watcher::Event::Apply(ci) | watcher::Event::InitApply(ci))) => {
                if let Err(e) = on_instance(&state, &ci).await {
                    tracing::warn!(error = format!("{e:#}"), "handling an instance update");
                }
            }
            Ok(Some(watcher::Event::Delete(ci))) => {
                if let Err(e) = on_instance_deleted(&state, &ci).await {
                    tracing::warn!(error = format!("{e:#}"), "handling an instance deletion");
                }
            }
            Ok(Some(_)) => {}
            Ok(None) => return,
            Err(e) => tracing::warn!(error = %e, "watching instances"),
        }
    }
}

async fn on_instance(state: &AppState, ci: &ChallengeInstance) -> anyhow::Result<()> {
    let name = ci.metadata.name.clone().unwrap_or_default();
    let Some(attempt) = db::attempt_by_instance(&state.db, &name).await? else {
        return Ok(()); // not created by the api (kubectl, tests...)
    };
    match ci.status.as_ref().and_then(|s| s.phase.as_ref()) {
        Some(ChallengeInstanceStatusPhase::Expired) => {
            db::end_attempt(&state.db, &name, "expired").await?
        }
        Some(ChallengeInstanceStatusPhase::Failed) => {
            db::end_attempt(&state.db, &name, "failed").await?
        }
        _ => {}
    }
    let view = instance_view(state, ci)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    state
        .hub
        .publish(attempt.user_id, Event::Instance { instance: view });
    Ok(())
}

async fn on_instance_deleted(state: &AppState, ci: &ChallengeInstance) -> anyhow::Result<()> {
    let name = ci.metadata.name.clone().unwrap_or_default();
    let Some(attempt) = db::attempt_by_instance(&state.db, &name).await? else {
        return Ok(());
    };
    db::end_attempt(&state.db, &name, "deleted").await?;
    state
        .hub
        .publish(attempt.user_id, Event::InstanceDeleted { id: name });
    Ok(())
}

async fn watch_check_runs(state: AppState, api: Api<CheckRun>) {
    let mut stream = watcher(api, watcher::Config::default())
        .default_backoff()
        .applied_objects()
        .boxed();
    loop {
        match stream.try_next().await {
            Ok(Some(run)) => {
                if let Err(e) = on_check_run(&state, &run).await {
                    tracing::warn!(error = format!("{e:#}"), "handling a check run update");
                }
            }
            Ok(None) => return,
            Err(e) => tracing::warn!(error = %e, "watching check runs"),
        }
    }
}

/// Records a finished check run and pushes it to its owner.
pub async fn on_check_run(state: &AppState, run: &CheckRun) -> anyhow::Result<()> {
    let Some(status) = run.status.as_ref() else {
        return Ok(());
    };
    let (phase, done) = match status.phase {
        Some(CheckRunStatusPhase::Completed) => ("Completed", true),
        Some(CheckRunStatusPhase::Error) => ("Error", true),
        Some(CheckRunStatusPhase::Running) => ("Running", false),
        _ => return Ok(()),
    };
    let name = run.metadata.name.clone().unwrap_or_default();
    let instance = run.spec.instance.clone();
    let Some(attempt) = db::attempt_by_instance(&state.db, &instance).await? else {
        return Ok(());
    };
    if !done {
        let mut row = db::latest_check_run(&state.db, attempt.id).await?;
        if let Some(row) = row.as_mut().filter(|r| r.name == name) {
            row.phase = phase.into();
            state.hub.publish(
                attempt.user_id,
                Event::Check {
                    check: check_view(row, &instance, vec![]),
                },
            );
        }
        return Ok(());
    }

    let results: Vec<db::TaskResult> = status
        .results
        .iter()
        .flatten()
        .map(|r| db::TaskResult {
            task: r.task.clone(),
            passed: r.passed,
            message: r.message.clone(),
        })
        .collect();
    // Points come from the installed package (the scoring source of truth is
    // the database from here on).
    let ch = state.cluster.challenge(&attempt.challenge).await?;
    let tasks = ch
        .as_ref()
        .and_then(views::package)
        .map(|p| p.spec.tasks.clone())
        .unwrap_or_default();
    let points: Vec<db::TaskPoints> = tasks
        .iter()
        .map(|t| db::TaskPoints {
            task: &t.id,
            points: t.points,
        })
        .collect();
    let solved = db::complete_check_run(
        &state.db,
        &name,
        phase,
        status.message.as_deref(),
        &results,
        &points,
    )
    .await?
    .map(|(_, solved)| solved)
    .unwrap_or_default();
    if !solved.is_empty() {
        tracing::info!(user = %attempt.user_id, challenge = attempt.challenge, tasks = ?solved, "tasks solved");
    }
    if let Some(row) = db::latest_check_run(&state.db, attempt.id)
        .await?
        .filter(|r| r.name == name)
    {
        state.hub.publish(
            attempt.user_id,
            Event::Check {
                check: check_view(&row, &instance, solved),
            },
        );
    }
    Ok(())
}
