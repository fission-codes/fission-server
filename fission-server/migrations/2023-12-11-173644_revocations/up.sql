CREATE TABLE revocations (
    id SERIAL PRIMARY KEY,
    cid TEXT NOT NULL UNIQUE,
    iss TEXT NOT NULL,
    challenge TEXT NOT NULL
);

CREATE INDEX idx_revocations_cid ON revocations (cid);
