# --- !Ups
create table "exported_diff_db_vulnerabilities" ("id" SERIAL NOT NULL PRIMARY KEY,"vulnerability_name" VARCHAR NOT NULL,"ticket_format_version" INTEGER NOT NULL);
create unique index "idx_exported_diff_db_vulnerabilities_vulnerabilityName" on "exported_diff_db_vulnerabilities" ("vulnerability_name");
create table "exported_diff_db_vulnerability_projects" ("exported_vulnerability_id" INTEGER NOT NULL,"full_project_id" VARCHAR NOT NULL);
create unique index "idx_exported_diff_db_vulnerability_projects_all" on "exported_diff_db_vulnerability_projects" ("exported_vulnerability_id","full_project_id");
create table "change" ("id" SERIAL NOT NULL PRIMARY KEY,"time" TIMESTAMP NOT NULL,"vulnerability_name" VARCHAR NOT NULL,"project_name" VARCHAR NOT NULL,"direction" VARCHAR NOT NULL);

# --- !Downs
drop table "change";
drop table "exported_diff_db_vulnerability_projects";
drop table "exported_diff_db_vulnerabilities";

