-- +goose Up
CREATE TABLE entries (
    id           BIGSERIAL   PRIMARY KEY,
    label_hash   BYTEA       NOT NULL,
    leaf         BYTEA       NOT NULL,
    record       BYTEA       NOT NULL,
    metadata     BYTEA,
    vrf_proof    BYTEA       NOT NULL,
    log_index    BIGINT,
    submitted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    included_at  TIMESTAMPTZ,
    CONSTRAINT entries_included_at_requires_index CHECK ((log_index IS NULL) = (included_at IS NULL))
);

CREATE UNIQUE INDEX entries_leaf_key ON entries (leaf);
CREATE UNIQUE INDEX entries_log_index_key ON entries (log_index) WHERE log_index IS NOT NULL;
CREATE INDEX entries_label_hash_idx ON entries (label_hash, log_index);
CREATE INDEX entries_pending_idx ON entries (id) WHERE log_index IS NULL;

-- +goose Down
DROP TABLE entries;
