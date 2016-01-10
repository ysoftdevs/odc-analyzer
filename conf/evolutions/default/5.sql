# --- !Ups

CREATE TABLE "cookie_authenticators" (
  "id"             VARCHAR   NOT NULL,
  "provider_id"    VARCHAR   NOT NULL,
  "provider_key"   VARCHAR   NOT NULL,
  "last_used"      TIMESTAMP NOT NULL,
  "expiration"     TIMESTAMP NOT NULL,
  "idle_timeout"   BIGINT    NULL,
  "cookie_max_age" BIGINT    NULL,
  "fingerprint"    VARCHAR   NULL
);

CREATE INDEX cookie_authenticators_id ON cookie_authenticators (id);

# --- !Downs

DROP TABLE cookie_authenticators;