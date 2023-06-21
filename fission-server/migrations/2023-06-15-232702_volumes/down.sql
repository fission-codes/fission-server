ALTER TABLE accounts
  DROP COLUMN volume_id;

ALTER TABLE apps
  DROP COLUMN volume_id;

DROP TABLE volumes;
