-- all code hashes would become invalid
TRUNCATE email_verifications;

ALTER TABLE email_verifications
  DROP COLUMN did;

-- there's not enough entropy to hash codes, so let's drop the security charade
ALTER TABLE email_verifications
  RENAME COLUMN code_hash TO code;
