-- User management (M5): disabled accounts and last sign-in.

ALTER TABLE users ADD COLUMN disabled_at timestamptz;
ALTER TABLE users ADD COLUMN last_login_at timestamptz;
