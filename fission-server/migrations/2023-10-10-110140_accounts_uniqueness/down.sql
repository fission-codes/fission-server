ALTER TABLE accounts
    DROP CONSTRAINT IF EXISTS unique_did,
    DROP CONSTRAINT IF EXISTS unique_username,
    DROP CONSTRAINT IF EXISTS unique_email;

ALTER TABLE accounts
    ALTER COLUMN username SET NOT NULL,
    ALTER COLUMN email SET NOT NULL;
