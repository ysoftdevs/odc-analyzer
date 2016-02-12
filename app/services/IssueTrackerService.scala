package services

import controllers.Vulnerability
import models.ExportedVulnerability

import scala.concurrent.Future

trait IssueTrackerService {
  def reportVulnerability(vulnerability: Vulnerability): Future[ExportedVulnerability[String]]
  def ticketLink(ticket: String): String
  def ticketLink(ticket: ExportedVulnerability[String]): String = ticketLink(ticket.ticket)
}
