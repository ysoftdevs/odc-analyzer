package controllers

import java.util.concurrent.atomic.AtomicBoolean
import javax.inject.Inject

import com.ysoft.concurrent.FutureLock._
import com.ysoft.odc.statistics.{FailedProjects, LibDepStatistics}
import com.ysoft.odc.{Absolutizer, ArtifactFile, ArtifactItem, SetDiff}
import models.{EmailMessageId, ExportedVulnerability}
import play.api.i18n.MessagesApi
import play.api.libs.Crypto
import play.api.mvc.Action
import play.api.{Configuration, Logger}
import services._
import views.html.DefaultRequest

import scala.concurrent.Future.{successful => Fut}
import scala.concurrent.{ExecutionContext, Future}

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
      val projects = dependencyCheckReportsParser.parseReports(successfulReports, failedReports).projectsReportInfo.sortedReportsInfo
      Ok(views.html.notifications.index(projects, myWatches, failedReports.keySet))
    }
  }

  //@inline private def filterMissingTickets(missingTickets: Set[String]) = missingTickets take 1 // for debug purposes
  @inline private def filterMissingTickets(missingTickets: Set[String]) = missingTickets // for production purposes

  private def notifyVulnerabilities[T](
    lds: LibDepStatistics, failedProjects: FailedProjects, ep: notificationService.ExportPlatform[T, _], projects: ProjectsWithReports
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
      projectUpdates <- Future.traverse(existingTicketsIds){ ticketId =>  // If we traversed over existingTicketsProjects, we would skip vulns with no projects
        val oldProjectIdsSet = existingTicketsProjects(ticketId)
        val exportedVulnerability = ticketsById(ticketId)
        val vulnerabilityName = exportedVulnerability.vulnerabilityName
        val failedOldProjects = oldProjectIdsSet.filter(failedProjects.isFailed)
        val newKnownProjectIdsSet = vulnerabilitiesByName(vulnerabilityName)._2.flatMap(_.projects).map(_.fullId)
        val allNewProjectIdsSet = newKnownProjectIdsSet ++ failedOldProjects  //If build for a project currently fails and it used to be affected, consider it as still affected. This prevents sudden switching these two states.
        val diff = new SetDiff(oldSet = oldProjectIdsSet, newSet = allNewProjectIdsSet)
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

  private def exportFailedReports(lds: LibDepStatistics, failed: FailedProjects): Future[Unit] = {
    if(failed.failedProjectsSet.nonEmpty){
      ???
    }else{
      Fut(())
    }
  }

  def cron(key: String, purgeCache: Boolean) = Action.async{
    if(Crypto.constantTimeEquals(key, config.getString("yssdc.cronKey").get)){
      futureLock(cronJobIsRunning) {
        if (purgeCache) {
          projectReportsProvider.purgeCache(Map())
        }
        val (lastRefreshTime, resultsFuture) = projectReportsProvider.resultsForVersions(versions)
        for {
          // TODO: process failedReports, parsedReports.failedAnalysises and successfulResults.filter(x => x._2._1.state != "Successful" || x._2._1.buildState != "Successful")
          (successfulReports, failedReports) <- resultsFuture
          libraries <- librariesService.all
          parsedReports = dependencyCheckReportsParser.parseReports(successfulReports, failedReports)
          lds = LibDepStatistics(dependencies = parsedReports.groupedDependencies.toSet, libraries = libraries.toSet, parsedReports = parsedReports)
          failed = lds.failedProjects
          failedReportsExportFuture = Fut(()) // TODO: exportFailedReports(lds, failed)
          issuesExportResultFuture = exportToIssueTracker(lds, failed, parsedReports.projectsReportInfo)
          diffDbExportResultFuture = exportToDiffDb(lds, failed, parsedReports.projectsReportInfo)
          mailExportResultFuture = emailExportServiceOption.map(_.exportType) match {
            case Some(EmailExportType.Vulnerabilities) => exportToEmail(lds, failed, parsedReports.projectsReportInfo).map((_: (_, _, _)) => ())
            case Some(EmailExportType.Digest) => diffDbExportResultFuture.flatMap(_ => exportToEmailDigest(lds, parsedReports.projectsReportInfo))
            case None => Future(())
          }
          (missingTickets, newTicketIds, updatedTickets) <- issuesExportResultFuture
          (_: Unit) <- mailExportResultFuture
          (missingVulns, newVulnIds, updatedVulns) <- diffDbExportResultFuture
          failedReportsExport <- failedReportsExportFuture
        } yield Ok(
          missingTickets.mkString("\n") + "\n\n" + newTicketIds.mkString("\n") + updatedTickets.toString
            //"\n\n" +
            //missingEmails.mkString("\n") + "\n\n" + newMessageIds.mkString("\n") + updatedEmails.toString
        )
      } whenLocked {
        Fut(ServiceUnavailable("A cron job seems to be running at this time"))
      }
    }else{
      Fut(Unauthorized("unauthorized"))
    }
  }

  private def forService[S, T](serviceOption: Option[S])(f: S => Future[(Set[String], Set[T], Set[Any])]) = serviceOption.fold(Fut((Set[String](), Set[T](), Set[Any]())))(f)

  private def exportToEmail(lds: LibDepStatistics, failedProjects: FailedProjects, p: ProjectsWithReports) = forService(emailExportServiceOption){ emailExportService =>
    notifyVulnerabilities[EmailMessageId](lds, failedProjects, notificationService.mailExport, p) { (vulnerability, dependencies) =>
      emailExportService.mailForVulnerability(vulnerability, dependencies).flatMap(emailExportService.sendEmail).map(id => ExportedVulnerability(vulnerability.name, EmailMessageId(id), 0))
    }{ (vuln, diff, msgid) =>
      emailExportService.mailForVulnerabilityProjectsChange(vuln, msgid, diff, p).flatMap(emailExportService.sendEmail).map(_ => ())
    }
  }

  // FIXME: In case of crash during export, one change might be exported multiple times. This can't be solved in e-mail exports, but it might be solved in issueTracker and diffDb exports.
  private def exportToIssueTracker(lds: LibDepStatistics, failedProjects: FailedProjects, p: ProjectsWithReports) = forService(issueTrackerServiceOption){ issueTrackerService =>
    notifyVulnerabilities[String](lds, failedProjects, notificationService.issueTrackerExport, p) { (vulnerability, dependencies) =>
      issueTrackerService.reportVulnerability(vulnerability, dependencies.flatMap{_.projects})
    }{ (vuln, diff, ticket) =>
      issueTrackerService.updateVulnerability(vuln, diff.map(p.parseUnfriendlyNameGracefully), ticket)
    }/*.flatMap{ v => <- Maybe this approach of migrating is completely wrong, because the issue tracker does not have access to the export DB.
      // Perform the migration after main operations, propagate exceptions, but don't change the resulting value
      issueTrackerService.migrateOldIssues().map((_: Unit) => v)
    }*/
  }

  private def exportToDiffDb(lds: LibDepStatistics, failedProjects: FailedProjects, p: ProjectsWithReports) = {
    notifyVulnerabilities[String](lds, failedProjects, notificationService.diffDbExport, p){ (vulnerability, dependencies) =>
      //?save_new_vulnerability
      val affectedProjects = dependencies.flatMap(_.projects)
      val diff = new SetDiff(Set(), affectedProjects)
      notificationService.changeAffectedProjects(vulnerability.name, diff.map(_.fullId)).map{_ =>
        ExportedVulnerability[String](vulnerabilityName = vulnerability.name, ticket = vulnerability.name, ticketFormatVersion = 0)
      }
    }{ (vulnerability, diff, id) =>
      notificationService.changeAffectedProjects(vulnerability.name, diff)
    }
  }

  private val emailDigestThrottler = new SingleFutureExecutionThrottler()

  private def exportToEmailDigest(lds: LibDepStatistics, p: ProjectsWithReports) = emailExportServiceOption.fold(Future.successful(())){ emailExportService =>
    notificationService.subscribers.flatMap{ subscribers =>
      Future.traverse(subscribers){ case (subscriber, subscriptions) =>
        emailDigestThrottler.throttle {
          notificationService.sendDigestToSubscriber(subscriber, subscriptions) {
            case Seq() => Future.successful(())
            case changes =>
              for {
                emailMessage <- emailExportService.emailDigest(subscriber, changes, p)
                (_: String) <- emailExportService.sendEmail(emailMessage)
              } yield ()
          }
        }
      }.map((_ : Iterable[Unit]) => ())
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
