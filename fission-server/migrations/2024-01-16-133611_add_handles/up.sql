ALTER TABLE accounts
  ADD COLUMN handle TEXT;

CREATE UNIQUE INDEX idx_accounts_handle ON accounts (handle);
