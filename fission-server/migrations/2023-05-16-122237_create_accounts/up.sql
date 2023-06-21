CREATE TABLE accounts (
  id SERIAL PRIMARY KEY,
  did TEXT NOT NULL,
  username TEXT NOT NULL,
  email TEXT NOT NULL,
  app_id SERIAL REFERENCES apps(id),
  inserted_at TIMESTAMP NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

ALTER TABLE apps
  ADD COLUMN owner_id SERIAL NOT NULL REFERENCES accounts(id);

SELECT diesel_manage_updated_at('accounts');
