TRUNCATE email_verifications;

ALTER TABLE email_verifications
  ADD COLUMN did TEXT NOT NULL;

ALTER TABLE email_verifications
  RENAME COLUMN code TO code_hash;
