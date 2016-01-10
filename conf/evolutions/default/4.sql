# --- !Ups

CREATE TABLE snooze(
  "id" SERIAL NOT NULL,
  "until" DATE NOT NULL,
  "snoozed_object_identifier" VARCHAR(512) NOT NULL,
  "reason" VARCHAR(1024) NOT NULL
);
CREATE INDEX snooze_until ON snooze (until);

# --- !Downs

DROP TABLE snooze;