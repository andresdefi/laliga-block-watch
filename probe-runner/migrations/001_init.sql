-- laliga-block-watch initial schema.
--
-- Design notes
--   * `probe_results` is the raw append-only feed from RIPE Atlas. One row per
--     (measurement, probe, target). Keep it narrow - summaries go elsewhere.
--   * `incidents` is the curated output of the detection engine. Every public
--     claim on the dashboard must link to at least one incident row whose
--     `evidence` JSON can be replayed against raw probe_results.
--   * `user_targets` is the citizen-submission queue. `verified = false` means
--     an operator has not yet sanity-checked the URL.
--   * `matches` is a local cache of the LaLiga fixture list so the detector
--     does not depend on football-data.org being reachable during a cycle.

CREATE TABLE IF NOT EXISTS probe_results (
    id              BIGSERIAL PRIMARY KEY,
    measurement_id  BIGINT       NOT NULL,
    probe_id        BIGINT       NOT NULL,
    asn             INTEGER,
    country_code    CHAR(2)      NOT NULL,
    target_ip       INET         NOT NULL,
    target_port     INTEGER      NOT NULL,
    target_label    TEXT         NOT NULL,
    observed_at     TIMESTAMPTZ  NOT NULL,
    outcome         TEXT         NOT NULL,           -- success | timeout | refused | other
    rtt_ms          DOUBLE PRECISION,
    raw             JSONB        NOT NULL
);

CREATE INDEX IF NOT EXISTS probe_results_target_time_idx
    ON probe_results (target_ip, observed_at DESC);
CREATE INDEX IF NOT EXISTS probe_results_asn_time_idx
    ON probe_results (asn, observed_at DESC);

CREATE TABLE IF NOT EXISTS incidents (
    id              BIGSERIAL PRIMARY KEY,
    target_ip       INET         NOT NULL,
    target_label    TEXT         NOT NULL,
    match_id        BIGINT,
    started_at      TIMESTAMPTZ  NOT NULL,
    ended_at        TIMESTAMPTZ,
    affected_asns   INTEGER[]    NOT NULL,
    evidence        JSONB        NOT NULL
);

CREATE INDEX IF NOT EXISTS incidents_started_idx
    ON incidents (started_at DESC);

CREATE TABLE IF NOT EXISTS user_targets (
    id              BIGSERIAL PRIMARY KEY,
    submitted_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    url             TEXT         NOT NULL,
    contact_email   TEXT,
    notes           TEXT,
    verified        BOOLEAN      NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS matches (
    id              BIGINT PRIMARY KEY,
    kickoff_utc     TIMESTAMPTZ  NOT NULL,
    home            TEXT         NOT NULL,
    away            TEXT         NOT NULL,
    status          TEXT         NOT NULL
);

CREATE INDEX IF NOT EXISTS matches_kickoff_idx
    ON matches (kickoff_utc);
