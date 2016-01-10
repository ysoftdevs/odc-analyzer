# --- !Ups

ALTER TABLE library_tag ADD COLUMN warning_order INT NULL DEFAULT NULL;

# --- !Downs

ALTER TABLE library_tag DROP COLUMN warning_order;
