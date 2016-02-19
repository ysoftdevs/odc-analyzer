package services

import java.util.NoSuchElementException
import javax.inject.Named

import com.ysoft.odc.{SetDiff, Absolutizer}
import controllers._
import models.EmailMessageId
import play.api.libs.mailer.{MailerClient, Email}

import scala.concurrent.{ExecutionContext, Future}

class EmailExportService(from: String, nobodyInterestedContact: String, mailerClient: MailerClient, notificationService: VulnerabilityNotificationService, emailSendingExecutionContext: ExecutionContext, absolutizer: Absolutizer)(implicit executionContext: ExecutionContext) {

  def recipientsForProjects(projects: Set[ReportInfo]) = for{
    recipients <- notificationService.getRecipientsForProjects(projects)
  } yield {
    recipients.map(_.providerKey) match { // TODO: get the email in a cleaner way
      case Seq() => Seq(nobodyInterestedContact) -> false
      case other => other -> true
    }
  }

  def mailForVulnerabilityProjectsChange(vuln: Vulnerability, emailMessageId: EmailMessageId, diff: SetDiff[String], projects: ProjectsWithReports) = {
    def showProjects(s: Set[String]) = s.map(p =>
      "* " + (try{
        friendlyProjectNameString(projects.parseUnfriendlyName(p))
      }catch{ // It might fail on project that has been removed
        case e: NoSuchElementException => s"unknown project $p"
      })
    ).mkString("\n")
    for{
      (recipients, somebodySubscribed) <- recipientsForProjects(diff.added.map(projects.parseUnfriendlyName))
    } yield Email(
      subject = s"[${vuln.name}] Modified vulnerability${if(!somebodySubscribed) ", nobody is subscribed for that" else "" }",
      from = from,
      to = Seq(),
      replyTo = emailMessageId.validIdOption,
      headers = emailMessageId.validIdOption.map("References" -> _).toSeq,
      bcc = recipients,
      bodyText = Some(
        "New projects affected by the vulnerability: \n"+showProjects(diff.added) + "\n\n" +
          "Projects no longer affected by the vulnerability: \n"+showProjects(diff.removed) + "\n\n" +
          s"More details: "+absolutizer.absolutize(routes.Statistics.vulnerability(vuln.name, None))
      )
    )
  }


  def sendEmail(email: Email): Future[String] = Future{
    mailerClient.send(email)
  }(emailSendingExecutionContext)

  def mailForVulnerability(vulnerability: Vulnerability, dependencies: Set[GroupedDependency]) = for {
    (recipientEmails, somebodySubscribed) <- recipientsForProjects(dependencies.flatMap(_.projects))
  } yield Email(
    subject = s"[${vulnerability.name}] New vulnerability${if(!somebodySubscribed) ", nobody is subscribed for that" else "" }",
    from = from,
    to = Seq(),
    bcc = recipientEmails,
    bodyText = Some(vulnerability.description + "\n\n" + s"More details: "+absolutizer.absolutize(routes.Statistics.vulnerability(vulnerability.name, None)))
  )

}
