-- Question bank schema. Plain types only, so it runs on SQLite and Postgres.
CREATE TABLE capabilities (
    name          TEXT PRIMARY KEY,
    kind          TEXT NOT NULL,
    escalate_only INTEGER NOT NULL,
    yes_meaning   TEXT NOT NULL,
    no_meaning    TEXT NOT NULL,
    flow_use      TEXT
);
CREATE TABLE context_facts (
    id                  TEXT PRIMARY KEY,
    name                TEXT NOT NULL,
    description         TEXT NOT NULL,
    collected_by        TEXT NOT NULL,
    match_rule          TEXT,
    fields_json         TEXT NOT NULL,
    has_unverified_seed INTEGER NOT NULL,
    version             INTEGER NOT NULL
);
CREATE TABLE explanations (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT NOT NULL
);
CREATE TABLE reason_codes (
    code        TEXT PRIMARY KEY,
    disposition TEXT NOT NULL,
    description TEXT NOT NULL
);
CREATE TABLE questions (
    id           TEXT PRIMARY KEY,
    text         TEXT NOT NULL,
    tests        TEXT NOT NULL REFERENCES explanations(id),
    capability   TEXT NOT NULL REFERENCES capabilities(name),
    inputs_json  TEXT NOT NULL,
    params_json  TEXT NOT NULL,
    source_json  TEXT NOT NULL,
    license_json TEXT NOT NULL,
    status       TEXT NOT NULL,
    version      INTEGER NOT NULL,
    influence    TEXT NOT NULL,       -- none | low | medium | high
    influence_by_source_json TEXT NOT NULL
);
CREATE TABLE question_needs (
    question_id TEXT NOT NULL REFERENCES questions(id),
    need_type   TEXT NOT NULL,   -- context | alert_field | param
    need_ref    TEXT NOT NULL,
    PRIMARY KEY (question_id, need_type, need_ref)
);
CREATE TABLE detections (
    id                 TEXT PRIMARY KEY,
    level              TEXT NOT NULL,   -- rule | technique
    name               TEXT NOT NULL,
    techniques_json    TEXT NOT NULL,
    data_source_json   TEXT NOT NULL,
    sigma_logsource_json TEXT NOT NULL,   -- offline matching metadata, never used at runtime
    sigma_refs_json    TEXT NOT NULL,
    alert_fields_json  TEXT NOT NULL,
    intent             TEXT,
    fp_quality         TEXT,
    fingerprint_json   TEXT NOT NULL,
    fingerprint_influence_json TEXT NOT NULL,   -- per-field attacker influence; sets Q0's rating
    precedent_entity   TEXT NOT NULL,
    precedent_validity TEXT NOT NULL,
    max_mode           TEXT,            -- recommend for technique fallbacks
    status             TEXT NOT NULL,
    version            INTEGER NOT NULL
);
CREATE TABLE flow_steps (
    detection_id TEXT NOT NULL REFERENCES detections(id),
    step         INTEGER NOT NULL,
    question_id  TEXT NOT NULL REFERENCES questions(id),
    on_yes       TEXT NOT NULL,
    on_no        TEXT NOT NULL,
    on_unknown   TEXT NOT NULL,
    bind_json    TEXT NOT NULL,
    influence_override TEXT,          -- step-level attacker influence (Q0 only)
    guards_json  TEXT NOT NULL,       -- [{question, when, then, bind}], run only when the step would close
    PRIMARY KEY (detection_id, step)
);
