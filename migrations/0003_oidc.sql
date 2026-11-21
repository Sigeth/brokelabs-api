-- Single sign-on (M5): accounts created by an OpenID Connect provider, and
-- sign-ins in progress.

ALTER TABLE users ADD COLUMN oidc_issuer text;
ALTER TABLE users ADD COLUMN oidc_subject text;
ALTER TABLE users ADD COLUMN email text;
CREATE UNIQUE INDEX users_oidc_identity ON users (oidc_issuer, oidc_subject)
    WHERE oidc_subject IS NOT NULL;

-- A sign-in sent to the provider, until it comes back (minutes).
CREATE TABLE oidc_logins (
    state         text PRIMARY KEY,
    nonce         text NOT NULL,
    pkce_verifier text NOT NULL,
    next_path     text NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now()
);
