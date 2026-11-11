//! End-to-end tests of the handlers, against PostgreSQL (skipped without
//! `OPSLAB_TEST_DATABASE_URL`) and an in-memory cluster.

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use opslab_auth::Verifier;
use opslab_types::{Challenge, ChallengeInstance, CheckRun};
use serde_json::{Value, json};
use tower::ServiceExt;

use crate::app::{AppState, router, test_state};
use crate::cluster::fake::FakeCluster;
use crate::{auth, db, events};

fn challenge() -> Challenge {
    serde_json::from_value(json!({
        "apiVersion": "opslab.io/v1alpha1",
        "kind": "Challenge",
        "metadata": {"name": "hello"},
        "spec": {"source": {"inline": {"package": {
            "apiVersion": "opslab.io/v1alpha1", "kind": "ChallengePackage",
            "metadata": {"name": "hello", "version": "0.1.0"},
            "spec": {"title": "Hello", "summary": "s", "category": "linux-hardening", "difficulty": "easy",
                     "machines": [{"name": "box", "runtime": "pod", "image": "x"}],
                     "access": {"terminals": [{"machine": "box"}]},
                     "tasks": [{"id": "t1", "title": "T1", "points": 10}]}}}}},
        "status": {
            "runnable": true, "digest": "sha256:x",
            "package": {
                "apiVersion": "opslab.io/v1alpha1", "kind": "ChallengePackage",
                "metadata": {"name": "hello", "version": "0.1.0"},
                "spec": {"title": "Hello", "summary": "Say hello.", "category": "linux-hardening", "difficulty": "easy",
                         "estimatedTime": "15m0s",
                         "machines": [{"name": "box", "runtime": "pod", "image": "x"}],
                         "access": {"terminals": [{"machine": "box", "user": "student", "label": "box"}]},
                         "tasks": [{"id": "t1", "title": "T1", "points": 10}, {"id": "t2", "title": "T2", "points": 5}]}}}
    }))
    .unwrap()
}

struct Client {
    app: Router,
    cookie: Option<String>,
}

impl Client {
    async fn send(&mut self, method: &str, uri: &str, body: Option<Value>) -> (StatusCode, Value) {
        let mut req = Request::builder()
            .method(method)
            .uri(uri)
            .header(header::ORIGIN, "http://opslab.test");
        if let Some(c) = &self.cookie {
            req = req.header(header::COOKIE, c);
        }
        let req = match body {
            Some(b) => req
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(b.to_string())),
            None => req.body(Body::empty()),
        }
        .unwrap();
        let res = self.app.clone().oneshot(req).await.unwrap();
        if let Some(set) = res.headers().get(header::SET_COOKIE) {
            self.cookie = Some(set.to_str().unwrap().split(';').next().unwrap().to_string());
        }
        let status = res.status();
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }
}

async fn setup() -> Option<(AppState, Arc<FakeCluster>, Client)> {
    let db = db::testing::database().await?;
    auth::bootstrap_solo(&db, "admin", Some("pw"))
        .await
        .unwrap();
    let cluster = Arc::new(FakeCluster::default());
    cluster.challenges.lock().unwrap().push(challenge());
    cluster
        .instructions
        .lock()
        .unwrap()
        .insert("hello".into(), "# Hello".into());
    let state = test_state(db, cluster.clone());
    let client = Client {
        app: router(state.clone(), None),
        cookie: None,
    };
    Some((state, cluster, client))
}

#[tokio::test]
async fn login() {
    let Some((_, _, mut c)) = setup().await else {
        return;
    };
    let (status, _) = c
        .send(
            "POST",
            "/api/v1/auth/login",
            Some(json!({"username": "admin", "password": "no"})),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, me) = c
        .send(
            "POST",
            "/api/v1/auth/login",
            Some(json!({"username": "admin", "password": "pw"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        (
            me["username"].as_str(),
            me["role"].as_str(),
            me["score"].as_i64()
        ),
        (Some("admin"), Some("admin"), Some(0))
    );
    assert_eq!(c.send("GET", "/api/v1/me", None).await.0, StatusCode::OK);
    assert_eq!(
        c.send("POST", "/api/v1/auth/logout", None).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        c.send("GET", "/api/v1/me", None).await.0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn cross_origin_writes_are_rejected() {
    let Some((state, _, _)) = setup().await else {
        return;
    };
    let req = Request::post("/api/v1/auth/login")
        .header(header::ORIGIN, "http://evil.inst.opslab.test")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({"username": "admin", "password": "pw"}).to_string(),
        ))
        .unwrap();
    let res = router(state, None).oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn play_a_challenge() {
    let Some((state, cluster, mut c)) = setup().await else {
        return;
    };
    c.send(
        "POST",
        "/api/v1/auth/login",
        Some(json!({"username": "admin", "password": "pw"})),
    )
    .await;

    // Catalog.
    let (status, list) = c.send("GET", "/api/v1/challenges", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(list[0]["name"], "hello");
    assert_eq!(
        (
            list[0]["points"].as_i64(),
            list[0]["estimatedMinutes"].as_i64()
        ),
        (Some(15), Some(15))
    );
    let (_, detail) = c.send("GET", "/api/v1/challenges/hello", None).await;
    assert_eq!(detail["instructions"], "# Hello");
    assert_eq!(detail["taskList"][1]["id"], "t2");
    assert_eq!(
        c.send("GET", "/api/v1/challenges/nope", None).await.0,
        StatusCode::NOT_FOUND
    );

    // Start: one instance at a time.
    let (status, inst) = c
        .send(
            "POST",
            "/api/v1/instances",
            Some(json!({"challenge": "hello"})),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{inst}");
    let id = inst["id"].as_str().unwrap().to_string();
    assert!(id.starts_with("hello-"));
    assert_eq!(inst["phase"], "Queued");
    let (status, _) = c
        .send(
            "POST",
            "/api/v1/instances",
            Some(json!({"challenge": "hello"})),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let created = cluster.instances.lock().unwrap().get(&id).cloned().unwrap();
    assert_eq!(created.spec.owner.display_name.as_deref(), Some("admin"));

    // Not ready yet: no terminal, no check.
    let terminal = format!("/api/v1/instances/{id}/terminals");
    assert_eq!(
        c.send("POST", &terminal, Some(json!({"machine": "box"})))
            .await
            .0,
        StatusCode::CONFLICT
    );

    // The operator makes it ready.
    let mut ready: ChallengeInstance = created.clone();
    ready.status = serde_json::from_value(
        json!({"phase": "Ready", "namespace": "inst-x", "expiresAt": "2030-01-01T00:00:00Z"}),
    )
    .unwrap();
    cluster.instances.lock().unwrap().insert(id.clone(), ready);
    let (_, list) = c.send("GET", "/api/v1/instances", None).await;
    assert_eq!(
        (list[0]["phase"].as_str(), list[0]["expiresAt"].as_str()),
        (Some("Ready"), Some("2030-01-01T00:00:00Z"))
    );

    // Terminal tokens are scoped to the instance and machine.
    let (status, access) = c
        .send("POST", &terminal, Some(json!({"machine": "box"})))
        .await;
    assert_eq!(status, StatusCode::OK);
    let url = access["url"].as_str().unwrap();
    let token = url.strip_prefix("ws://gw.test/v1/terminal?token=").unwrap();
    let claims = Verifier::from_jwks(&state.signer.jwks())
        .unwrap()
        .verify(token)
        .unwrap();
    assert_eq!(claims.grant.instance, format!("opslab-instances/{id}"));
    assert_eq!(claims.grant.machine, "box");
    assert_eq!(
        c.send("POST", &terminal, Some(json!({"machine": "other"})))
            .await
            .0,
        StatusCode::NOT_FOUND
    );

    // Check: a CheckRun owned by the instance, then the operator's result.
    let checks = format!("/api/v1/instances/{id}/checks");
    let (status, check) = c.send("POST", &checks, None).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(check["phase"], "Pending");
    assert_eq!(c.send("POST", &checks, None).await.0, StatusCode::CONFLICT);
    let run: CheckRun = cluster.check_runs.lock().unwrap()[0].clone();
    assert_eq!(run.metadata.owner_references.as_ref().unwrap()[0].name, id);

    let mut events = Box::pin(state.hub.subscribe(c_user(&state).await));
    let mut done = run.clone();
    done.status = serde_json::from_value(json!({"phase": "Completed", "results": [
        {"task": "t1", "passed": true, "message": "ok"}, {"task": "t2", "passed": false, "message": "not yet"}]})).unwrap();
    events::on_check_run(&state, &done).await.unwrap();
    events::on_check_run(&state, &done).await.unwrap(); // replay: no double score
    let event = serde_json::to_value(futures::StreamExt::next(&mut events).await.unwrap()).unwrap();
    assert_eq!(event["type"], "check");
    assert_eq!(event["check"]["newlySolved"], json!(["t1"]));

    let (_, me) = c.send("GET", "/api/v1/me", None).await;
    assert_eq!(me["score"], 10);
    let (_, latest) = c.send("GET", &checks, None).await;
    assert_eq!(latest["results"][1]["message"], "not yet");
    let (_, list) = c.send("GET", "/api/v1/challenges", None).await;
    assert_eq!(
        (
            list[0]["solvedPoints"].as_i64(),
            list[0]["solvedTasks"].as_i64()
        ),
        (Some(10), Some(1))
    );

    // Stop: the instance goes, the score stays, a new one can start.
    assert_eq!(
        c.send("DELETE", &format!("/api/v1/instances/{id}"), None)
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    assert!(cluster.instances.lock().unwrap().is_empty());
    assert_eq!(
        c.send("GET", &format!("/api/v1/instances/{id}"), None)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        c.send(
            "POST",
            "/api/v1/instances",
            Some(json!({"challenge": "hello"}))
        )
        .await
        .0,
        StatusCode::CREATED
    );
}

async fn c_user(state: &AppState) -> uuid::Uuid {
    db::user_by_name(&state.db, "admin")
        .await
        .unwrap()
        .unwrap()
        .id
}
