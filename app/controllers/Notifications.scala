package controllers

import java.net.URLEncoder
import java.util.concurrent.atomic.AtomicBoolean
import javax.inject.Inject

import com.ysoft.odc.{Absolutizer, SetDiff}
import controllers.Statistics.LibDepStatistics
import models.{EmailMessageId, ExportedVulnerability}
import play.api.i18n.MessagesApi
import play.api.libs.Crypto
import play.api.mvc.{RequestHeader, Action}
import play.api.{Configuration, Logger}
import services.{EmailExportService, IssueTrackerService, LibrariesService, VulnerabilityNotificationService}
import views.html.DefaultRequest

import scala.concurrent.Future.{successful => Fut}
import scala.concurrent.{ExecutionContext, Future}
import com.ysoft.concurrent.FutureLock._

class Notifications @Inject()(
  config: Configuration,
  librariesService: LibrariesService,
  notificationService: VulnerabilityNotificationService,
  projectReportsProvider: ProjectReportsProvider,
  dependencyCheckReportsParser: DependencyCheckReportsParser,
  issueTrackerServiceOption: Option[IssueTrackerService],
  emailExportServiceOption: Option[EmailExportService],
  absolutizer: Absolutizer,
  val env: AuthEnv
)(implicit val messagesApi: MessagesApi, executionContext: ExecutionContext) extends AuthenticatedController {

  private val versions = Map[String, Int]()

  private val cronJobIsRunning = new AtomicBoolean()

  import secureRequestConversion._

  def listProjects() = SecuredAction.async { implicit req =>
    val (lastRefreshTime, resultsFuture) = projectReportsProvider.resultsForVersions(versions)
    val myWatchesFuture = notificationService.watchedProjectsByUser(req.identity.loginInfo).map(_.map(_.project).toSet)
    for{
      (successfulReports, failedReports) <- resultsFuture
      myWatches <- myWatchesFuture
    } yield {
      val projects = dependencyCheckReportsParser.parseReports(successfulReports).projectsReportInfo.sortedReportsInfo
      Ok(views.html.notifications.index(projects, myWatches))
    }
  }

  //@inline private def filterMissingTickets(missingTickets: Set[String]) = missingTickets take 1 // for debug purposes
  @inline private def filterMissingTickets(missingTickets: Set[String]) = missingTickets // for production purposes

  def notifyVulnerabilities[T](
    lds: LibDepStatistics, ep: notificationService.ExportPlatform[T, _], projects: ProjectsWithReports
  )(
    reportVulnerability: (Vulnerability, Set[GroupedDependency]) => Future[ExportedVulnerability[T]]
  )(
    reportChangedProjectsForVulnerability: (Vulnerability, SetDiff[String], T) => Future[Unit]
  ) = {
    val vulnerabilitiesByName = lds.vulnerabilitiesToDependencies.map{case (v, deps) => (v.name, (v, deps))}
    for{
      tickets <- ep.ticketsForVulnerabilities(lds.vulnerabilityNames)
      // Check existing tickets
      existingTicketsIds = tickets.values.map(_._1).toSet
      ticketsById = tickets.values.map{case (id, ev) => id -> ev}.toMap
      existingTicketsProjects <- ep.projectsForTickets(existingTicketsIds)
      _ = Logger.warn("existingTicketsProjects for "+ep+": "+existingTicketsProjects.filter(_._2.exists(_.toLowerCase.contains("wps"))).toString)
      projectUpdates <- Future.traverse(existingTicketsIds){ ticketId =>  // If we traversed over existingTicketsProjects, we would skip vulns with no projects
        val oldProjectIdsSet = existingTicketsProjects(ticketId)
        val exportedVulnerability = ticketsById(ticketId)
        val vulnerabilityName = exportedVulnerability.vulnerabilityName
        val newProjectIdsSet = vulnerabilitiesByName(vulnerabilityName)._2.flatMap(_.projects).map(_.fullId)
        val diff = new SetDiff(oldSet = oldProjectIdsSet, newSet = newProjectIdsSet)
        if(diff.nonEmpty) {
          reportChangedProjectsForVulnerability(lds.vulnerabilitiesByName(vulnerabilityName), diff, exportedVulnerability.ticket).flatMap { _ =>
            ep.changeProjects(ticketId, diff, projects)
          }.map( _ => Some(diff))
        } else {
          Fut(None)
        }
      }
      // Check new tickets
      missingTickets = vulnerabilitiesByName.keySet -- tickets.keySet
      newTicketIds <- Future.traverse(filterMissingTickets(missingTickets)){vulnerabilityName =>
        val (vulnerability, dependencies) = vulnerabilitiesByName(vulnerabilityName)
        reportVulnerability(vulnerability, dependencies).flatMap{ ticket =>
          ep.addTicket(ticket, dependencies.flatMap(_.projects)).map(_ => ticket.ticket)
        }
      }
    } yield (missingTickets, newTicketIds, projectUpdates.toSet: Set[Any])
  }

  def cron(key: String, purgeCache: Boolean) = Action.async{
    if(Crypto.constantTimeEquals(key, config.getString("yssdc.cronKey").get)){
      futureLock(cronJobIsRunning) {
        if (purgeCache) {
          projectReportsProvider.purgeCache(Map())
        }
        val (lastRefreshTime, resultsFuture) = projectReportsProvider.resultsForVersions(versions)
        for {
          (successfulReports, failedReports) <- resultsFuture
          libraries <- librariesService.all
          parsedReports = dependencyCheckReportsParser.parseReports(successfulReports)
          lds = LibDepStatistics(dependencies = parsedReports.groupedDependencies.toSet, libraries = libraries.toSet)
          issuesExportResultFuture = exportToIssueTracker(lds, parsedReports.projectsReportInfo)
          mailExportResultFuture = exportToEmail(lds, parsedReports.projectsReportInfo)
          (missingTickets, newTicketIds, updatedTickets) <- issuesExportResultFuture
          (missingEmails, newMessageIds, updatedEmails) <- mailExportResultFuture
        } yield Ok(
          missingTickets.mkString("\n") + "\n\n" + newTicketIds.mkString("\n") + updatedTickets.toString +
            "\n\n" +
            missingEmails.mkString("\n") + "\n\n" + newMessageIds.mkString("\n") + updatedEmails.toString
        )
      } whenLocked {
        Fut(ServiceUnavailable("A cron job seems to be running at this time"))
      }
    }else{
      Fut(Unauthorized("unauthorized"))
    }
  }

  private def forService[S, T](serviceOption: Option[S])(f: S => Future[(Set[String], Set[T], Set[Any])]) = serviceOption.fold(Fut((Set[String](), Set[T](), Set[Any]())))(f)

  private def exportToEmail(lds: LibDepStatistics, p: ProjectsWithReports) = forService(emailExportServiceOption){ emailExportService =>
    notifyVulnerabilities[EmailMessageId](lds, notificationService.mailExport, p) { (vulnerability, dependencies) =>
      emailExportService.mailForVulnerability(vulnerability, dependencies).flatMap(emailExportService.sendEmail).map(id => ExportedVulnerability(vulnerability.name, EmailMessageId(id), 0))
    }{ (vuln, diff, msgid) =>
      emailExportService.mailForVulnerabilityProjectsChange(vuln, msgid, diff, p).flatMap(emailExportService.sendEmail).map(_ => ())
    }
  }

  private def exportToIssueTracker(lds: LibDepStatistics, p: ProjectsWithReports) = forService(issueTrackerServiceOption){ issueTrackerService =>
    notifyVulnerabilities[String](lds, notificationService.issueTrackerExport, p) { (vulnerability, dependencies) =>
      issueTrackerService.reportVulnerability(vulnerability)
    }{ (vuln, diff, ticket) =>
      Fut(())
    }
  }

  // Redirection to a specific position does not look intuituve now, so it has been disabled for now.
  private def redirectToProject(project: String)(implicit th: DefaultRequest) = Redirect(routes.Notifications.listProjects()/*.withFragment("project-" + URLEncoder.encode(project, "utf-8")).absoluteURL()*/)

  def watch(project: String) = SecuredAction.async{ implicit req =>
    for( _ <-notificationService.subscribe(req.identity.loginInfo, project) ) yield redirectToProject(project)
  }

  def unwatch(project: String) = SecuredAction.async{ implicit req =>
    for( _ <-notificationService.unsubscribe(req.identity.loginInfo, project) ) yield redirectToProject(project)
  }

}
