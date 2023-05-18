CREATE TABLE apps (
  id SERIAL PRIMARY KEY,
  cid TEXT,
  inserted_at TIMESTAMP NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

SELECT diesel_manage_updated_at('apps');
