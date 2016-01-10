# --- !Ups


CREATE TABLE library (
  id SERIAL,
  library_type VARCHAR(255) NOT NULL, -- We could use enums, but it is too much bothering in PostgreSQL. We'll enforce those constrainst on application level :)
  identifier VARCHAR(255) NOT NULL,
  classified BOOLEAN,
  PRIMARY KEY (id)
);

CREATE UNIQUE INDEX library_unique ON library (library_type, identifier);

CREATE TABLE library_tag (
  id SERIAL,
  name varchar(255) NOT NULL,
  PRIMARY KEY (id)
);

CREATE UNIQUE INDEX library_tag_unique ON library_tag (name);

CREATE TABLE library_to_library_tag (
  library_id INTEGER NOT NULL REFERENCES library,
  library_tag_id INTEGER NOT NULL REFERENCES library_tag,
  context_dependent BOOLEAN
);

CREATE UNIQUE INDEX library_to_library_tag_unique ON library_to_library_tag (library_id, library_tag_id);

# --- !Downs

DROP TABLE library;
DROP TABLE library_to_library_tag;
DROP TABLE library_tag;
