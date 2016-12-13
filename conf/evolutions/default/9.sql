# --- !Ups
ALTER TABLE "exported_diff_db_vulnerabilities" ADD "done" BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE "exported_email_vulnerabilities" ADD "done" BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE "exported_issue_tracker_vulnerabilities" ADD "done" BOOLEAN NOT NULL DEFAULT FALSE;

CREATE INDEX "idx_exported_diff_db_vulnerabilities_done" ON "exported_diff_db_vulnerabilities" ("done");
CREATE INDEX "idx_exported_email_vulnerabilities_done" ON "exported_email_vulnerabilities" ("done");
CREATE INDEX "idx_exported_issue_tracker_vulnerabilities_done" ON "exported_issue_tracker_vulnerabilities" ("done");

# --- !Downs
DROP INDEX "idx_exported_diff_db_vulnerabilities_done";
DROP INDEX "idx_exported_email_vulnerabilities_done";
DROP INDEX "idx_exported_issue_tracker_vulnerabilities_done";

ALTER TABLE "exported_diff_db_vulnerabilities" DROP COLUMN "done";
ALTER TABLE "exported_email_vulnerabilities" DROP COLUMN "done";
ALTER TABLE "exported_issue_tracker_vulnerabilities" DROP COLUMN "done";
