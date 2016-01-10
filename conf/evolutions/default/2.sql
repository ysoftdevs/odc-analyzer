# --- !Ups

ALTER TABLE library_tag ADD COLUMN note VARCHAR(1024) NULL DEFAULT NULL;

# --- !Downs

ALTER TABLE library_tag DROP COLUMN note;
