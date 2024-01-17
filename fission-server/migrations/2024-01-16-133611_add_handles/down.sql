DROP INDEX idx_accounts_handle;

ALTER TABLE accounts
  DROP COLUMN handle;
