ALTER TABLE accounts
    ALTER COLUMN username DROP NOT NULL,
    ALTER COLUMN email DROP NOT NULL;

ALTER TABLE accounts
    ADD CONSTRAINT unique_did UNIQUE (did),
    ADD CONSTRAINT unique_username UNIQUE (username),
    ADD CONSTRAINT unique_email UNIQUE (email);
