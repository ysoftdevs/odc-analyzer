# --- !Ups
create table "vulnerability_subscription" ("subscriber_provider_id" VARCHAR NOT NULL,"subscriber_provider_key" VARCHAR NOT NULL,"project" VARCHAR NOT NULL);
create unique index "all" on "vulnerability_subscription" ("subscriber_provider_id","subscriber_provider_key","project");
create table "exported_issue_tracker_vulnerabilities" ("id" SERIAL NOT NULL PRIMARY KEY,"vulnerability_name" VARCHAR NOT NULL,"ticket" VARCHAR NOT NULL,"ticket_format_version" INTEGER NOT NULL);
create unique index "idx_exported_issue_tracker_vulnerabilities_vulnerabilityName" on "exported_issue_tracker_vulnerabilities" ("vulnerability_name");
create unique index "idx_ticket" on "exported_issue_tracker_vulnerabilities" ("ticket");
create table "exported_issue_tracker_vulnerability_projects" ("exported_vulnerability_id" INTEGER NOT NULL,"full_project_id" VARCHAR NOT NULL);
create unique index "idx_exported_issue_tracker_vulnerability_projects_all" on "exported_issue_tracker_vulnerability_projects" ("exported_vulnerability_id","full_project_id");
create table "exported_email_vulnerabilities" ("id" SERIAL NOT NULL PRIMARY KEY,"vulnerability_name" VARCHAR NOT NULL,"message_id" VARCHAR NOT NULL,"ticket_format_version" INTEGER NOT NULL);
create unique index "idx_exported_email_vulnerabilities_vulnerabilityName" on "exported_email_vulnerabilities" ("vulnerability_name");
create table "exported_email_vulnerability_projects" ("exported_vulnerability_id" INTEGER NOT NULL,"full_project_id" VARCHAR NOT NULL);
create unique index "idx_exported_email_vulnerability_projects_all" on "exported_email_vulnerability_projects" ("exported_vulnerability_id","full_project_id");

# --- !Downs
drop table "exported_email_vulnerability_projects";
drop table "exported_email_vulnerabilities";
drop table "exported_issue_tracker_vulnerability_projects";
drop table "exported_issue_tracker_vulnerabilities";
drop table "vulnerability_subscription";

