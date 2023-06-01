CREATE TABLE email_verifications (
    id SERIAL PRIMARY KEY,

    inserted_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),

    email TEXT NOT NULL,
    did TEXT NOT NULL,
    code_hash TEXT NOT NULL
);

SELECT diesel_manage_updated_at('email_verifications');