package services

import com.ysoft.odc.SetDiff
import controllers.{ReportInfo, Vulnerability}
import models.ExportedVulnerability

import scala.concurrent.Future

trait IssueTrackerService {
  def reportVulnerability(vulnerability: Vulnerability, projects: Set[ReportInfo]): Future[ExportedVulnerability[String]]
  def ticketLink(ticket: String): String
  def ticketLink(ticket: ExportedVulnerability[String]): String = ticketLink(ticket.ticket)
  def updateVulnerability(vuln: Vulnerability, diff: SetDiff[ReportInfo], ticket: String): Future[Unit]
  //def migrateOldIssues(): Future[Unit]
}
