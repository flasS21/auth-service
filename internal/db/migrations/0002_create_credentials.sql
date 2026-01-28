-- Project Keystone: credentials (email/password auth)
-- Phase-6 migration

BEGIN;

CREATE TABLE credentials (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),

    user_id uuid NOT NULL
        REFERENCES users(id)
        ON DELETE CASCADE,

    password_hash text NOT NULL,

    hash_version text NOT NULL,

    created_at timestamptz NOT NULL DEFAULT NOW(),
    updated_at timestamptz NOT NULL DEFAULT NOW(),

    CONSTRAINT credentials_user_unique
        UNIQUE (user_id)
);

CREATE INDEX credentials_user_id_idx
ON credentials (user_id);

COMMIT;
