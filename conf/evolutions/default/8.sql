# --- !Ups
CREATE TABLE "notification_digest_status" (
  "user_provider_id" VARCHAR NOT NULL,
  "user_provider_key" VARCHAR NOT NULL,
  "last_changelog_id" INTEGER NULL
);
CREATE UNIQUE INDEX "notification_digest_status_user_idx" ON "notification_digest_status" ("user_provider_id","user_provider_key");

INSERT INTO notification_digest_status
(user_provider_id, user_provider_key, last_changelog_id)
  SELECT
    subscriber_provider_id  AS user_provider_id,
    subscriber_provider_key AS user_provider_key,
    (SELECT MAX(id) from change) AS last_changelog_id
  FROM vulnerability_subscription
  GROUP BY subscriber_provider_id, subscriber_provider_key;

ALTER TABLE change ADD COLUMN "notified_to_somebody" BOOLEAN NOT NULL DEFAULT FALSE;
UPDATE change SET notified_to_somebody = TRUE;

# --- !Downs
drop table "notification_digest_status";

ALTER TABLE change DROP COLUMN "notified_to_somebody";
