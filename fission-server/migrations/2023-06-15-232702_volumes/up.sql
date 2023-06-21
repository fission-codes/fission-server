CREATE TABLE volumes (
    id SERIAL PRIMARY KEY,

    inserted_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),

    cid TEXT NOT NULL
);

ALTER TABLE accounts
  ADD COLUMN volume_id INTEGER REFERENCES volumes(id);

ALTER TABLE apps
  ADD COLUMN volume_id INTEGER REFERENCES volumes(id);

SELECT diesel_manage_updated_at('volumes');
