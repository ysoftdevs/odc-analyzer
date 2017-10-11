package services

import java.util.NoSuchElementException

import com.mohiva.play.silhouette.api.LoginInfo
import com.ysoft.html.HtmlWithText
import com.ysoft.html.HtmlWithText._
import com.ysoft.odc.{Absolutizer, SetDiff}
import controllers._
import models.Change.Direction
import models.{Change, EmailMessageId}
import play.api.libs.mailer.{Email, MailerClient}
import play.twirl.api.{Html, HtmlFormat}

import scala.concurrent.{ExecutionContext, Future}

object EmailExportType extends Enumeration {
  val Vulnerabilities = Value("vulnerabilities")
  val Digest = Value("digest")


}
object EmailExportService {

  private object VulnerabilityDescription{
    def apply(name: String, v: Option[Vulnerability]): VulnerabilityDescription = v.fold(UnknownVulnerabilityDescription(name))(new StandardVulnerabilityDescription(_))
  }

  private abstract class VulnerabilityDescription {
    def name: String
    def description: String
    def cvssScore: Option[Double]
  }

  private final class StandardVulnerabilityDescription(vulnerability: Vulnerability) extends VulnerabilityDescription {
    override def name: String = vulnerability.name
    override def description: String = vulnerability.description
    override def cvssScore: Option[Double] = vulnerability.cvssScore
  }

  private final class UnknownVulnerabilityDescription(override val name: String, link: String) extends VulnerabilityDescription {
    override def description: String = s"Unknown vulnerability. Try looking at the following address for more details: $link"
    override def cvssScore: Option[Double] = None
  }

  private final class TotallyUnknownVulnerabilityDescription(override val name: String) extends VulnerabilityDescription {
    override def description: String = s"Unknown vulnerability. Not even sure where to look for other details. Maybe Googling the identifier will help."
    override def cvssScore: Option[Double] = None
  }

  private object UnknownVulnerabilityDescription {
    def apply(name: String): VulnerabilityDescription = name match {
      case cveId if name startsWith "CVE-" => new UnknownVulnerabilityDescription(name, s"https://nvd.nist.gov/vuln/detail/$cveId")
      case ossIndexId if name startsWith "OSSINDEX-" => new UnknownVulnerabilityDescription(name, s"https://ossindex.net/resource/vulnerability/$ossIndexId")
      case other => new TotallyUnknownVulnerabilityDescription(other)
    }
  }

}

class EmailExportService(from: String, nobodyInterestedContact: String, val exportType: EmailExportType.Value, odcService: OdcDbService, mailerClient: MailerClient, notificationService: VulnerabilityNotificationService, emailSendingExecutionContext: ExecutionContext, absolutizer: Absolutizer)(implicit executionContext: ExecutionContext) {
  // Maybe it is not the best place for exportType, but I am not sure if we want this to be configurable. If no, then we can get rid of it. If yes, we should refactor it.

  import EmailExportService.VulnerabilityDescription

  private def getEmail(loginInfo: LoginInfo) = loginInfo.providerKey // TODO: get the email in a cleaner way

  def recipientsForProjects(projects: Set[ReportInfo]) = for{
    recipients <- notificationService.getRecipientsForProjects(projects)
  } yield {
    recipients.map(getEmail) match {
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



  def emailDigest(subscriber: LoginInfo, changes: Seq[Change], projects: ProjectsWithReports): Future[Email] = {
    val vulnNames = changes.map(_.vulnerabilityName).toSet
    for {
      vulns <- Future.traverse(vulnNames.toSeq)(name => odcService.getVulnerabilityDetails(name).map(v => name -> VulnerabilityDescription(name, v))).map(_.toMap)
      groups = changes.groupBy(_.direction).withDefaultValue(Seq())
    } yield {
      val changesMarks = Map(Direction.Added -> "❢", Direction.Removed -> "☑")
      def heading(level: Int)(s: String) = HtmlWithText(
        html = Html("<h"+level+">"+HtmlFormat.escape(s)+"</h"+level+">"),
        text = ("#"*level) + s + "\n"
      )
      def moreInfo(link: String) = HtmlWithText(
        text = "more info: "+link,
        html = Html("<a href=\""+HtmlFormat.escape(link)+"\">more info</a>")
      )
      def vulnerabilityText(change: Change, vulnerability: VulnerabilityDescription): HtmlWithText = (
        heading(4)(s"${changesMarks(change.direction)} ${vulnerability.name}${vulnerability.cvssScore.fold("")(sev => s" (CVSS severity: $sev)")}")
        + justHtml("<p>") + plainText(vulnerability.description) + justHtml("<br>") + justText("\n")
        + moreInfo(absolutizer.absolutize(routes.Statistics.vulnerability(vulnerability.name, None))) + justHtml("</p>")
      )
      def vulnChanges(changes: Seq[Change]): HtmlWithText =
        changes.map(c => c -> vulns(c.vulnerabilityName))
          .sortBy{case (change, vuln) => (vuln.cvssScore.map(-_), vuln.name)}
          .map((vulnerabilityText _).tupled)
          .mkHtmlWithText(justText("\n\n"))
      def vulnerableProjects(projectIdToChanges: Map[String, Seq[Change]]): HtmlWithText =
        projectIdToChanges.toIndexedSeq.map{case (project, ch) => (projects.parseUnfriendlyNameGracefully(project), ch)}
          .sortBy{case (ri, _) => friendlyProjectNameString(ri).toLowerCase}
          .map{case (project, changes) => heading(3)(friendlyProjectNameString(project))+vulnChanges(changes)}
          .mkHtmlWithText(justText("\n\n"))
      def section(title: String, direction: Direction): Option[HtmlWithText] = {
        groups(direction) match {
          case Seq() => None
          case list => Some(heading(2)(title) + justText("\n") + vulnerableProjects(list.groupBy(_.projectName)))
        }
      }
      val body = Seq(
        section("Projects newly affected by a vulnerability", Direction.Added),
        section("Projects no longer affected by a vulnerability", Direction.Removed)
      ).flatten.mkHtmlWithText(justText("\n\n"))
      Email(
        subject = s"New changes in vulnerabilities (${changes.size}: +${groups(Direction.Added).size} -${groups(Direction.Removed).size})",
        to = Seq(getEmail(subscriber)),
        from = from,
        bodyText = Some(body.text),
        bodyHtml = Some(body.html.toString)
      )
    }
  }

}
