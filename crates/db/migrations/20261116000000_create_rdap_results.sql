-- RDAP query results for the `db` crate.
--
-- One row per queried IP address (the dequeue UPSERTs, so this is the
-- latest-known state per address). `address` is a proper `inet` column: the
-- dequeue stores single start-addresses as host routes (/32 for v4, /128 for v6),
-- which Postgres normalises so lookups and the primary-key UPSERT stay
-- consistent. The RDAP body is stored as `jsonb` (bound as text with a cast);
-- an advertised RFC 9877 geofeed is stored alongside as raw CSV bytes.

CREATE TABLE rdap_results (
    address      inet        PRIMARY KEY,
    registry     text        NOT NULL,
    job_id       bigint,
    request_url  text,
    response     jsonb       NOT NULL,
    geofeed_href text,
    geofeed_csv  bytea,
    queried_at   timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX rdap_results_registry_idx ON rdap_results (registry);
