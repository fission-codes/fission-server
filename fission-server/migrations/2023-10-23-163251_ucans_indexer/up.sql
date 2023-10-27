CREATE TABLE ucans (
    id SERIAL PRIMARY KEY,
    cid TEXT NOT NULL UNIQUE,
    encoded TEXT NOT NULL,

    issuer TEXT NOT NULL,
    audience TEXT NOT NULL,

    not_before TIMESTAMP,
    expires_at TIMESTAMP
);

CREATE UNIQUE INDEX idx_ucans_cid ON ucans (cid);

CREATE INDEX idx_ucans_issuer ON ucans (issuer);

CREATE INDEX idx_ucans_audience ON ucans (audience);


CREATE TABLE capabilities (
    id SERIAL PRIMARY KEY,

    resource TEXT NOT NULL,
    ability TEXT NOT NULL,

    caveats JSONB NOT NULL,

    ucan_id INTEGER NOT NULL
        REFERENCES ucans(id)
        ON DELETE CASCADE
);

CREATE INDEX idx_capabilities_resource ON capabilities (resource);

CREATE INDEX idx_capabilities_ability ON capabilities (ability);
