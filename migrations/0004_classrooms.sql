-- Classrooms (M5): a teacher's group of students, joined through an invite
-- link (D55), and the challenges assigned to it with their deadlines.

CREATE TABLE classrooms (
    id             uuid PRIMARY KEY,
    name           text NOT NULL,
    description    text NOT NULL DEFAULT '',
    -- A user owning classrooms cannot be deleted: give them to someone else first.
    owner_id       uuid NOT NULL REFERENCES users (id) ON DELETE RESTRICT,
    -- Uppercase, without the dash shown to people.
    invite_code    text NOT NULL UNIQUE,
    invite_enabled boolean NOT NULL DEFAULT true,
    created_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX classrooms_owner_id ON classrooms (owner_id);

CREATE TABLE classroom_members (
    classroom_id uuid NOT NULL REFERENCES classrooms (id) ON DELETE CASCADE,
    user_id      uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    joined_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (classroom_id, user_id)
);
CREATE INDEX classroom_members_user_id ON classroom_members (user_id);

-- Late work counts and is flagged (D58): solves after due_at are late.
CREATE TABLE assignments (
    id           uuid PRIMARY KEY,
    classroom_id uuid NOT NULL REFERENCES classrooms (id) ON DELETE CASCADE,
    challenge    text NOT NULL,
    opens_at     timestamptz,
    due_at       timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now(),
    UNIQUE (classroom_id, challenge),
    CHECK (opens_at IS NULL OR due_at IS NULL OR opens_at < due_at)
);
