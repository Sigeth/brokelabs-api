//! End-to-end tests of the handlers, against PostgreSQL (skipped without
//! `BROKELABS_TEST_DATABASE_URL`) and an in-memory cluster.

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use brokelabs_auth::Verifier;
use brokelabs_types::{Challenge, ChallengeInstance, CheckRun};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use crate::app::{AppState, router, test_state};
use crate::cluster::fake::FakeCluster;
use crate::{auth, db, events};

fn challenge() -> Challenge {
    serde_json::from_value(json!({
        "apiVersion": "brokelabs.io/v1alpha1",
        "kind": "Challenge",
        "metadata": {"name": "hello"},
        "spec": {"source": {"inline": {"package": {
            "apiVersion": "brokelabs.io/v1alpha1", "kind": "ChallengePackage",
            "metadata": {"name": "hello", "version": "0.1.0"},
            "spec": {"title": "Hello", "summary": "s", "category": "linux-hardening", "difficulty": "easy",
                     "machines": [{"name": "box", "runtime": "pod", "image": "x"}],
                     "access": {"terminals": [{"machine": "box"}]},
                     "tasks": [{"id": "t1", "title": "T1", "points": 10}]}}}}},
        "status": {
            "runnable": true, "digest": "sha256:x",
            "package": {
                "apiVersion": "brokelabs.io/v1alpha1", "kind": "ChallengePackage",
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
            .header(header::ORIGIN, "http://brokelabs.test");
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
    auth::bootstrap_admin(&db, "admin", Some("pw"))
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
        .header(header::ORIGIN, "http://evil.inst.brokelabs.test")
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
    assert_eq!(claims.grant.instance, format!("brokelabs-instances/{id}"));
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

fn catalog_source() -> brokelabs_types::CatalogSource {
    let perms = json!({"runtimes": ["vm"], "cpu": "1", "memory": "1Gi", "egress": "none"});
    serde_json::from_value(json!({
        "apiVersion": "brokelabs.io/v1alpha1",
        "kind": "CatalogSource",
        "metadata": {"name": "official"},
        "spec": {"ref": "ghcr.io/x/catalog:latest", "trust": {"keyless": [{"issuer": "https://i", "subjectRegExp": ".*"}]}},
        "status": {
            "signer": "ci (https://i)",
            "conditions": [{"type": "Ready", "status": "True", "reason": "Synced", "message": "1 packages listed",
                            "lastTransitionTime": "2026-11-15T10:00:00Z"}],
            "packages": [{"name": "ssh-hardening", "title": "SSH hardening", "category": "linux-hardening", "difficulty": "easy",
                "versions": [{"version": "1.1.0", "ref": "ghcr.io/x/ssh@sha256:b", "permissions": perms},
                             {"version": "1.0.0", "ref": "ghcr.io/x/ssh@sha256:a", "permissions": perms}]}]
        }
    }))
    .unwrap()
}

async fn sign_in(c: &mut Client, username: &str, password: &str) {
    let (status, _) = c
        .send(
            "POST",
            "/api/v1/auth/login",
            Some(json!({"username": username, "password": password})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn install_from_the_marketplace() {
    let Some((_, cluster, mut c)) = setup().await else {
        return;
    };
    cluster
        .catalog_sources
        .lock()
        .unwrap()
        .push(catalog_source());
    sign_in(&mut c, "admin", "pw").await;

    let (status, catalogs) = c.send("GET", "/api/v1/admin/catalogs", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        (
            catalogs[0]["ready"].as_bool(),
            catalogs[0]["packages"].as_u64()
        ),
        (Some(true), Some(1))
    );

    let (_, entries) = c.send("GET", "/api/v1/admin/marketplace", None).await;
    let entry = &entries[0];
    assert_eq!(entry["name"], "ssh-hardening");
    assert_eq!(entry["versions"][0]["permissions"]["cpu"], "1");
    assert!(entry["installed"].is_null());

    // Install the older version: an update is then offered.
    let (status, installed) = c
        .send(
            "PUT",
            "/api/v1/admin/challenges/ssh-hardening",
            Some(json!({"source": "official", "version": "1.0.0"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{installed}");
    assert_eq!(installed["requestedVersion"], "1.0.0");
    let ch = cluster
        .challenges
        .lock()
        .unwrap()
        .iter()
        .find(|c| c.metadata.name.as_deref() == Some("ssh-hardening"))
        .cloned()
        .unwrap();
    let src = ch.spec.source.catalog.unwrap();
    assert_eq!(
        (src.source.as_str(), src.version.as_str()),
        ("official", "1.0.0")
    );

    // Unlisted versions and challenges installed otherwise are refused.
    let (status, _) = c
        .send(
            "PUT",
            "/api/v1/admin/challenges/ssh-hardening",
            Some(json!({"source": "official", "version": "9.9.9"})),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = c
        .send(
            "PUT",
            "/api/v1/admin/challenges/hello",
            Some(json!({"source": "official", "version": "1.0.0"})),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "hello is not listed");

    // Removing the source removes what was installed from it (D43).
    assert_eq!(
        c.send("DELETE", "/api/v1/admin/catalogs/official", None)
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    let (_, installed) = c.send("GET", "/api/v1/admin/challenges", None).await;
    let names: Vec<&str> = installed
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|i| i["name"].as_str())
        .collect();
    assert_eq!(names, ["hello"]);
}

#[tokio::test]
async fn add_a_catalog_source() {
    let Some((_, cluster, mut c)) = setup().await else {
        return;
    };
    sign_in(&mut c, "admin", "pw").await;
    let (status, _) = c
        .send(
            "POST",
            "/api/v1/admin/catalogs",
            Some(json!({"name": "school", "ref": "registry.school/catalog:latest", "trust": {}})),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a source must trust someone"
    );
    let (status, created) = c
        .send(
            "POST",
            "/api/v1/admin/catalogs",
            Some(
                json!({"name": "school", "ref": "registry.school/catalog:latest",
                        "trust": {"keys": ["-----BEGIN PUBLIC KEY-----\n..."]}}),
            ),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let sources = cluster.catalog_sources.lock().unwrap();
    assert_eq!(sources[0].spec.trust.keys.as_ref().map(Vec::len), Some(1));
    assert_eq!(sources[0].spec.trust.allow_unsigned, None);
}

#[tokio::test]
async fn students_cannot_use_the_marketplace() {
    let Some((state, _, mut c)) = setup().await else {
        return;
    };
    db::create_user(
        &state.db,
        "bob",
        "Bob",
        "student",
        &auth::hash_password("pw").unwrap(),
    )
    .await
    .unwrap();
    sign_in(&mut c, "bob", "pw").await;
    for (method, uri) in [
        ("GET", "/api/v1/admin/marketplace"),
        ("GET", "/api/v1/admin/catalogs"),
        ("DELETE", "/api/v1/admin/challenges/hello"),
    ] {
        assert_eq!(
            c.send(method, uri, None).await.0,
            StatusCode::FORBIDDEN,
            "{method} {uri}"
        );
    }
}

async fn try_sign_in(c: &mut Client, username: &str, password: &str) -> StatusCode {
    c.send(
        "POST",
        "/api/v1/auth/login",
        Some(json!({"username": username, "password": password})),
    )
    .await
    .0
}

#[tokio::test]
async fn manage_users() {
    let Some((state, cluster, mut admin)) = setup().await else {
        return;
    };
    assert_eq!(try_sign_in(&mut admin, "admin", "pw").await, StatusCode::OK);

    // Create a student: the generated password works once shown.
    let (status, created) = admin
        .send(
            "POST",
            "/api/v1/admin/users",
            Some(json!({"username": "Alice", "displayName": "Alice A.", "role": "student"})),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!(created["user"]["username"], "alice");
    let id = created["user"]["id"].as_str().unwrap().to_string();
    let password = created["password"].as_str().unwrap().to_string();
    let (status, _) = admin
        .send(
            "POST",
            "/api/v1/admin/users",
            Some(json!({"username": "alice", "role": "student"})),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, _) = admin
        .send(
            "POST",
            "/api/v1/admin/users",
            Some(json!({"username": "bob", "role": "root"})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let mut alice = Client {
        app: router(state.clone(), None),
        cookie: None,
    };
    assert_eq!(
        try_sign_in(&mut alice, "alice", &password).await,
        StatusCode::OK
    );
    let (status, _) = alice.send("GET", "/api/v1/admin/users", None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Alice changes her password.
    let (status, _) = alice
        .send(
            "POST",
            "/api/v1/me/password",
            Some(json!({"currentPassword": "wrong", "newPassword": "long enough"})),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = alice
        .send(
            "POST",
            "/api/v1/me/password",
            Some(json!({"currentPassword": password, "newPassword": "short"})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = alice
        .send(
            "POST",
            "/api/v1/me/password",
            Some(json!({"currentPassword": password, "newPassword": "long enough"})),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        alice.send("GET", "/api/v1/me", None).await.0,
        StatusCode::OK
    );

    // Alice starts an instance; disabling her ends her session and stops it.
    let (status, _) = alice
        .send(
            "POST",
            "/api/v1/instances",
            Some(json!({"challenge": "hello"})),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(cluster.instances.lock().unwrap().len(), 1);
    let (status, view) = admin
        .send(
            "PATCH",
            &format!("/api/v1/admin/users/{id}"),
            Some(json!({"disabled": true, "role": "teacher"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{view}");
    assert_eq!(
        (view["disabled"].as_bool(), view["role"].as_str()),
        (Some(true), Some("teacher"))
    );
    assert!(cluster.instances.lock().unwrap().is_empty());
    assert_eq!(
        alice.send("GET", "/api/v1/me", None).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        try_sign_in(&mut alice, "alice", "long enough").await,
        StatusCode::FORBIDDEN
    );

    // Enabled again, with a reset password.
    admin
        .send(
            "PATCH",
            &format!("/api/v1/admin/users/{id}"),
            Some(json!({"disabled": false})),
        )
        .await;
    let (_, reset) = admin
        .send("POST", &format!("/api/v1/admin/users/{id}/password"), None)
        .await;
    let password = reset["password"].as_str().unwrap();
    assert_eq!(
        try_sign_in(&mut alice, "alice", "long enough").await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        try_sign_in(&mut alice, "alice", password).await,
        StatusCode::OK
    );

    // The admin cannot lock themselves out.
    let (_, list) = admin.send("GET", "/api/v1/admin/users", None).await;
    assert_eq!(list.as_array().unwrap().len(), 2);
    let me = list[0]["id"].as_str().unwrap();
    for body in [json!({"role": "student"}), json!({"disabled": true})] {
        let (status, _) = admin
            .send("PATCH", &format!("/api/v1/admin/users/{me}"), Some(body))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
    let (status, _) = admin
        .send("DELETE", &format!("/api/v1/admin/users/{me}"), None)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Deleting Alice.
    let (status, _) = admin
        .send("DELETE", &format!("/api/v1/admin/users/{id}"), None)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        alice.send("GET", "/api/v1/me", None).await.0,
        StatusCode::UNAUTHORIZED
    );
    let (_, list) = admin.send("GET", "/api/v1/admin/users", None).await;
    assert_eq!(list.as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn settings_need_no_session() {
    let Some((_, _, mut c)) = setup().await else {
        return;
    };
    let (status, settings) = c.send("GET", "/api/v1/settings", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(settings["mode"], "solo");
}

/// The state in organization mode (classrooms on).
fn organization(mut state: AppState) -> AppState {
    state.config = Arc::new(
        crate::config::Config::from_env_map(&[
            ("BROKELABS_DATABASE_URL", "postgres://localhost/unused"),
            ("BROKELABS_GATEWAY_URL", "http://gw.test"),
            ("BROKELABS_ALLOWED_ORIGINS", "http://brokelabs.test"),
            ("BROKELABS_MODE", "organization"),
        ])
        .unwrap(),
    );
    state
}

fn client(state: &AppState) -> Client {
    Client {
        app: router(state.clone(), None),
        cookie: None,
    }
}

/// Creates an account through the admin and signs it in.
async fn account(state: &AppState, admin: &mut Client, username: &str, role: &str) -> Client {
    let (status, created) = admin
        .send(
            "POST",
            "/api/v1/admin/users",
            Some(json!({"username": username, "role": role})),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let mut c = client(state);
    let password = created["password"].as_str().unwrap();
    assert_eq!(
        try_sign_in(&mut c, username, password).await,
        StatusCode::OK
    );
    c
}

#[tokio::test]
async fn run_a_classroom() {
    let Some((state, _, _)) = setup().await else {
        return;
    };
    let state = organization(state);
    let mut admin = client(&state);
    assert_eq!(try_sign_in(&mut admin, "admin", "pw").await, StatusCode::OK);
    let mut teacher = account(&state, &mut admin, "tess", "teacher").await;
    let mut other = account(&state, &mut admin, "otto", "teacher").await;

    // The teacher creates a classroom: its invite link is on.
    let (status, class) = teacher
        .send(
            "POST",
            "/api/v1/teach/classrooms",
            Some(json!({"name": " Class 1A "})),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{class}");
    assert_eq!(
        (class["name"].as_str(), class["inviteEnabled"].as_bool()),
        (Some("Class 1A"), Some(true))
    );
    let id = class["id"].as_str().unwrap().to_string();
    let code = class["inviteCode"].as_str().unwrap().to_string();
    assert_eq!(code.len(), 9);

    // Anyone with the link sees what it leads to, and signs up through it.
    let mut student = client(&state);
    let (status, invite) = student
        .send(
            "GET",
            &format!("/api/v1/invites/{}", code.to_lowercase()),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        (invite["classroom"].as_str(), invite["teacher"].as_str()),
        (Some("Class 1A"), Some("tess"))
    );
    let (status, me) = student
        .send(
            "POST",
            &format!("/api/v1/invites/{code}/signup"),
            Some(json!({"displayName": "Sam", "username": "sam", "password": "long enough"})),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{me}");
    assert_eq!(me["role"], "student");
    let (status, _) = client(&state)
        .send(
            "POST",
            &format!("/api/v1/invites/{code}/signup"),
            Some(json!({"displayName": "Sam 2", "username": "sam", "password": "long enough"})),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);

    // An existing user joins once.
    let (_, joined) = other
        .send("POST", &format!("/api/v1/invites/{code}/join"), None)
        .await;
    assert_eq!(joined["joined"], true);
    let (_, joined) = other
        .send("POST", &format!("/api/v1/invites/{code}/join"), None)
        .await;
    assert_eq!(joined["joined"], false);

    // Assignments: an installed challenge, with a deadline already past.
    let (status, _) = teacher
        .send(
            "PUT",
            &format!("/api/v1/teach/classrooms/{id}/assignments/nope"),
            Some(json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = teacher
        .send(
            "PUT",
            &format!("/api/v1/teach/classrooms/{id}/assignments/hello"),
            Some(json!({"opensAt": "2026-02-01T00:00:00Z", "dueAt": "2026-01-01T00:00:00Z"})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, a) = teacher
        .send(
            "PUT",
            &format!("/api/v1/teach/classrooms/{id}/assignments/hello"),
            Some(json!({"dueAt": "2026-01-01T00:00:00Z"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{a}");
    assert_eq!(a["title"], "Hello");

    // The student sees it, and a solve after the deadline is late.
    let (_, mine) = student.send("GET", "/api/v1/classrooms", None).await;
    assert_eq!(mine[0]["teacher"], "tess");
    assert_eq!(mine[0]["assignments"][0]["summary"]["title"], "Hello");
    assert_eq!(mine[0]["assignments"][0]["late"], false);
    sqlx::query("INSERT INTO solves (user_id, challenge, task, points) SELECT id, 'hello', 't1', 10 FROM users WHERE username = 'sam'")
        .execute(&state.db)
        .await
        .unwrap();
    let (_, mine) = student.send("GET", "/api/v1/classrooms", None).await;
    assert_eq!(
        (
            mine[0]["assignments"][0]["late"].as_bool(),
            mine[0]["assignments"][0]["done"].as_bool()
        ),
        (Some(true), Some(false))
    );

    // The teacher's view.
    let (_, detail) = teacher
        .send("GET", &format!("/api/v1/teach/classrooms/{id}"), None)
        .await;
    assert_eq!(detail["members"].as_array().unwrap().len(), 2);
    assert_eq!(detail["assignments"][0]["challenge"], "hello");

    // Other teachers and students cannot manage it.
    let (status, _) = other
        .send("GET", &format!("/api/v1/teach/classrooms/{id}"), None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (_, list) = other.send("GET", "/api/v1/teach/classrooms", None).await;
    assert!(list.as_array().unwrap().is_empty());
    let (status, _) = student.send("GET", "/api/v1/teach/classrooms", None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = teacher
        .send(
            "PATCH",
            &format!("/api/v1/teach/classrooms/{id}"),
            Some(json!({"ownerId": detail["members"][0]["id"]})),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Turning the link off, then rotating it.
    teacher
        .send(
            "PATCH",
            &format!("/api/v1/teach/classrooms/{id}"),
            Some(json!({"inviteEnabled": false})),
        )
        .await;
    let (status, _) = client(&state)
        .send("GET", &format!("/api/v1/invites/{code}"), None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    teacher
        .send(
            "PATCH",
            &format!("/api/v1/teach/classrooms/{id}"),
            Some(json!({"inviteEnabled": true})),
        )
        .await;
    let (_, rotated) = teacher
        .send(
            "POST",
            &format!("/api/v1/teach/classrooms/{id}/invite"),
            None,
        )
        .await;
    let new_code = rotated["inviteCode"].as_str().unwrap();
    assert_ne!(new_code, code);
    let (status, _) = client(&state)
        .send("GET", &format!("/api/v1/invites/{code}"), None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = client(&state)
        .send("GET", &format!("/api/v1/invites/{new_code}"), None)
        .await;
    assert_eq!(status, StatusCode::OK);

    // A teacher owning classrooms is not deleted until they are given away.
    let (_, users) = admin.send("GET", "/api/v1/admin/users", None).await;
    let uid = |name: &str| {
        users
            .as_array()
            .unwrap()
            .iter()
            .find(|u| u["username"] == name)
            .unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let (status, _) = admin
        .send(
            "DELETE",
            &format!("/api/v1/admin/users/{}", uid("tess")),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, _) = admin
        .send(
            "PATCH",
            &format!("/api/v1/teach/classrooms/{id}"),
            Some(json!({"ownerId": uid("sam")})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, moved) = admin
        .send(
            "PATCH",
            &format!("/api/v1/teach/classrooms/{id}"),
            Some(json!({"ownerId": uid("otto")})),
        )
        .await;
    assert_eq!(
        (status, moved["ownerName"].as_str()),
        (StatusCode::OK, Some("otto"))
    );
    let (status, _) = admin
        .send(
            "DELETE",
            &format!("/api/v1/admin/users/{}", uid("tess")),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Removing a member, then the classroom.
    let (status, _) = other
        .send(
            "DELETE",
            &format!("/api/v1/teach/classrooms/{id}/members/{}", uid("sam")),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, mine) = student.send("GET", "/api/v1/classrooms", None).await;
    assert!(mine.as_array().unwrap().is_empty());
    let (status, _) = other
        .send("DELETE", &format!("/api/v1/teach/classrooms/{id}"), None)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn classrooms_are_off_in_solo_mode() {
    let Some((_, _, mut c)) = setup().await else {
        return;
    };
    assert_eq!(try_sign_in(&mut c, "admin", "pw").await, StatusCode::OK);
    let (status, _) = c.send("GET", "/api/v1/teach/classrooms", None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, mine) = c.send("GET", "/api/v1/classrooms", None).await;
    assert_eq!((status, mine), (StatusCode::OK, json!([])));
}
