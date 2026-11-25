-- Generic durable job queue for the `db` crate.
--
-- A topic-partitioned work queue with at-least-once delivery:
--   * `topic`         — logical queue name (e.g. 'nro-delegations').
--   * `partition_key` — grouping used for round-robin claiming (e.g. the RIR
--                       registry), so one consumer interleaves groups instead of
--                       stalling on one group's long run.
--   * `dedup_key`     — optional idempotency key; a partial unique index makes
--                       `INSERT .. ON CONFLICT DO NOTHING` a no-op for repeats.
--   * `status`        — pending | running | done | failed.
--   * `locked_until`  — lease expiry; a crashed worker's running row becomes
--                       claimable again once this passes.
--   * `attempts`      — incremented on each claim, drives retry/backoff.
--
-- No `IF NOT EXISTS`: sqlx tracks applied migrations and runs each file once.

CREATE TABLE queue_jobs (
    id            bigserial     PRIMARY KEY,
    topic         text          NOT NULL,
    payload       text          NOT NULL,
    partition_key text          NOT NULL DEFAULT '',
    dedup_key     text,
    status        text          NOT NULL DEFAULT 'pending',
    attempts      integer       NOT NULL DEFAULT 0,
    locked_until  timestamptz,
    last_error    text,
    created_at    timestamptz   NOT NULL DEFAULT now(),
    updated_at    timestamptz   NOT NULL DEFAULT now()
);

-- Backs the claim scan: filter by (topic, status, availability), order by
-- (partition_key, id) for the round-robin.
CREATE INDEX queue_jobs_claim_idx
    ON queue_jobs (topic, status, locked_until, partition_key, id);

-- Backs the per-partition LATERAL seek (`topic, partition_key ORDER BY id`)
-- restricted to claimable rows, so the inner `LIMIT 1` is an index-only seek.
CREATE INDEX queue_jobs_partition_idx
    ON queue_jobs (topic, partition_key, id)
    WHERE status IN ('pending', 'running');

-- Idempotent enqueue: only enforced when a dedup_key is supplied.
CREATE UNIQUE INDEX queue_jobs_dedup_idx
    ON queue_jobs (topic, dedup_key)
    WHERE dedup_key IS NOT NULL;
