-- Example schema for the `db` crate.
--
-- A single `widgets` table demonstrating the column types and the insert /
-- query / list / count patterns that consumers copy for their own tables.
-- `gen_random_uuid()` is a core Postgres function (since PG13), so no pgcrypto
-- extension is required.
--
-- No `IF NOT EXISTS`: sqlx tracks applied migrations in `_sqlx_migrations` and
-- runs each file exactly once, so the guard is redundant and would only mask
-- schema drift if a divergent table pre-existed.

CREATE TABLE widgets (
    id         uuid          PRIMARY KEY DEFAULT gen_random_uuid(),
    name       text          NOT NULL,
    created_at timestamptz   NOT NULL DEFAULT now()
);

-- Backs `list_widgets`'s `ORDER BY created_at DESC, id DESC` (both columns,
-- matching direction, so the sort is index-only).
CREATE INDEX idx_widgets_created_at ON widgets (created_at DESC, id DESC);
