-- People and progress. Running state lives in Kubernetes (D8).

CREATE TABLE users (
    id            uuid PRIMARY KEY,
    username      text NOT NULL UNIQUE,
    display_name  text NOT NULL,
    password_hash text,
    role          text NOT NULL CHECK (role IN ('admin', 'teacher', 'student')),
    created_at    timestamptz NOT NULL DEFAULT now()
);

-- Browser sessions. Only a hash of the cookie value is stored.
CREATE TABLE sessions (
    token_hash bytea PRIMARY KEY,
    user_id    uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL
);
CREATE INDEX sessions_user_id ON sessions (user_id);

-- One attempt per ChallengeInstance. Kept after the instance is gone.
CREATE TABLE attempts (
    id                uuid PRIMARY KEY,
    user_id           uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    challenge         text NOT NULL,
    challenge_version text NOT NULL,
    instance_name     text NOT NULL UNIQUE,
    started_at        timestamptz NOT NULL DEFAULT now(),
    ended_at          timestamptz,
    end_reason        text
);
-- Default limit: one active instance per user.
CREATE UNIQUE INDEX attempts_one_active_per_user ON attempts (user_id) WHERE ended_at IS NULL;

-- Every validation request, with its results (history for teachers and a
-- future exam mode).
CREATE TABLE check_runs (
    id           uuid PRIMARY KEY,
    attempt_id   uuid NOT NULL REFERENCES attempts (id) ON DELETE CASCADE,
    name         text NOT NULL UNIQUE,
    requested_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz,
    phase        text NOT NULL DEFAULT 'Pending',
    message      text,
    results      jsonb
);
CREATE INDEX check_runs_attempt_id ON check_runs (attempt_id);

-- Solved tasks: the score. A task is solved once per user and challenge.
CREATE TABLE solves (
    user_id      uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    challenge    text NOT NULL,
    task         text NOT NULL,
    points       integer NOT NULL,
    solved_at    timestamptz NOT NULL DEFAULT now(),
    check_run_id uuid REFERENCES check_runs (id) ON DELETE SET NULL,
    PRIMARY KEY (user_id, challenge, task)
);
