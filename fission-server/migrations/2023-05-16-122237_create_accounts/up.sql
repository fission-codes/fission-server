CREATE TABLE accounts (
  id SERIAL PRIMARY KEY,
  did TEXT NOT NULL,
  username TEXT NOT NULL,
  verified BOOLEAN NOT NULL DEFAULT false,
  email TEXT NOT NULL CHECK (app_id IS NULL),
  app_id INTEGER REFERENCES apps(id),
  inserted_at TIMESTAMP NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

ALTER TABLE apps
  ADD COLUMN owner_id INTEGER NOT NULL REFERENCES accounts(id);

SELECT diesel_manage_updated_at('accounts');
