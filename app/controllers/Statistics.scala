package controllers

import com.github.nscala_time.time.Imports._
import com.google.inject.Inject
import com.google.inject.name.Named
import com.ysoft.odc.Confidence.Confidence
import com.ysoft.odc.statistics.{LibDepStatistics, TagStatistics}
import com.ysoft.odc._
import controllers.DependencyCheckReportsParser.ResultWithSelection
import controllers.api.{ApiConfig, ApiController}
import models.LibraryTag
import org.joda.time.DateTime
import play.api.i18n.MessagesApi
import play.api.libs.json._
import play.twirl.api.Txt
import services._
import views.html.DefaultRequest

import scala.concurrent.{ExecutionContext, Future}

final case class ScannedRepository(url: String, branch: String)

final case class ScannedProject(name: String, repos: Seq[ScannedRepository], teams: Seq[String], key: String)

final case class GroupedDependencyIdentifier(hashes: Hashes, identifiers: Seq[Identifier])

object GroupedDependencyIdentifier{
  def fromGroupedDependency(groupedDependency: GroupedDependency): GroupedDependencyIdentifier = GroupedDependencyIdentifier(
    hashes = groupedDependency.hashes,
    identifiers = groupedDependency.identifiersWithFilenames(threshold = Confidence.Highest)
  )
}

final case class GroupedDependencyDetailedIdentifier(hashes: Hashes, identifiers: Seq[Identifier], evidence: Seq[Evidence], fileNames: Seq[String])

object GroupedDependencyDetailedIdentifier{
  def fromGroupedDependency(groupedDependency: GroupedDependency) = GroupedDependencyDetailedIdentifier(
    hashes = groupedDependency.hashes,
    identifiers = groupedDependency.identifiers.toIndexedSeq.sortBy(_.name),
    evidence = groupedDependency.evidenceCollected.toIndexedSeq.sortBy(e => (e.name, e.value)),
    fileNames = groupedDependency.fileNames.toIndexedSeq.sortBy(_.toLowerCase)
  )

}

object Statistics{

  // TODO: Move this to a better place


  implicit val hashesWrites = Writes[Hashes](h => JsString(h.serialized))
  implicit val confidenceWrites = Writes[Confidence](c => JsString(c.toString))
  implicit val identifierWrites = Json.writes[Identifier]
  implicit val evidenceWrites = Json.writes[Evidence]
  implicit val groupedDependencyIdentifierWrites = Json.writes[GroupedDependencyIdentifier]
  implicit val groupedDependencyDetailedIdentifierWrites = Json.writes[GroupedDependencyDetailedIdentifier]
  //implicit val groupedDependencyFormats = Json.format[GroupedDependency]

}

//noinspection TypeAnnotation
class Statistics @Inject()(
  reportsParser: DependencyCheckReportsParser,
  reportsProcessor: DependencyCheckReportsProcessor,
  projectReportsProvider: ProjectReportsProvider,
  dependencyCheckReportsParser: DependencyCheckReportsParser,
  librariesService: LibrariesService,
  tagsService: TagsService,
  odcService: OdcService,
  libraryTagAssignmentsService: LibraryTagAssignmentsService,
  @Named("missing-GAV-exclusions") missingGAVExclusions: MissingGavExclusions,
  projects: Projects,
  vulnerabilityNotificationService: VulnerabilityNotificationService,
  issueTrackerServiceOption: Option[IssueTrackerService],
  protected val apiConfig: ApiConfig,
  val env: AuthEnv
)(implicit val messagesApi: MessagesApi, executionContext: ExecutionContext) extends AuthenticatedController with ApiController {

  private val versions = Map[String, Int]()

  import Statistics._

  private def notFound()(implicit req: DefaultRequest) = {
    NotFound(views.html.defaultpages.notFound("GET", req.uri))
  }

  import secureRequestConversion._


  private def select(allResults: (Map[String, (Build, ArtifactItem, ArtifactFile)], Map[String, Throwable]), selectorOption: Option[String]): Option[ResultWithSelection] = select(allResults._1, allResults._2, selectorOption)
  private def select(successfulResults: Map[String, (Build, ArtifactItem, ArtifactFile)], failedResults: Map[String, Throwable], selectorOption: Option[String]): Option[ResultWithSelection] = dependencyCheckReportsParser.parseReports(successfulResults, failedResults).selection(selectorOption)

  def searchVulnerableSoftware(versionlessCpes: Seq[String], versionOption: Option[String]) = ReadAction.async{ implicit req =>
    if(versionlessCpes.isEmpty){
      Future.successful(notFound())
    }else{
      val now = DateTime.now()
      val oldDataThreshold = 2.days
      val lastDbUpdateFuture = odcService.loadLastDbUpdate()
      val isOldFuture = lastDbUpdateFuture.map{ lastUpdate => now - oldDataThreshold > lastUpdate}
      versionOption match {
        case Some(version) =>
          for {
            res1 <- Future.traverse(versionlessCpes) { versionlessCpe => odcService.findRelevantCpes(versionlessCpe, version) }
            vulnIds = res1.flatten.map(_.vulnerabilityId).toSet
            vulns <- Future.traverse(vulnIds)(id => odcService.getVulnerabilityDetails(id).map(_.get))
            isOld <- isOldFuture
          } yield Ok(views.html.statistics.vulnerabilitiesForLibrary(
            vulnsAndVersionOption = Some((vulns, version)),
            cpes = versionlessCpes,
            isDbOld = isOld
          ))
        case None =>
          for(isOld <- isOldFuture) yield Ok(views.html.statistics.vulnerabilitiesForLibrary(
            vulnsAndVersionOption = None,
            cpes = versionlessCpes,
            isDbOld = isOld
          ))
      }
    }
  }

  def basic(selectorOption: Option[String]) = ReadAction.async{ implicit req =>
    val (lastRefreshTime, resultsFuture) = projectReportsProvider.resultsForVersions(versions)
    resultsFuture flatMap { allResults =>
      select(allResults, selectorOption).fold(Future.successful(notFound())){ selection =>
        val tagsFuture = tagsService.all
        val parsedReports = selection.result
        for{
          tagStatistics <- statisticsForTags(parsedReports, tagsFuture)
          libraries <- librariesService.all
        } yield Ok(views.html.statistics.basic(
          tagStatistics = tagStatistics,
          projectsWithSelection = selection.projectsWithSelection,
          parsedReports = parsedReports,
          lds = LibDepStatistics(libraries.toSet, parsedReports.groupedDependencies.toSet, parsedReports)
        ))
      }
    }
  }

  def statisticsForTags(parsedReports: DependencyCheckReportsParser.Result, tagsFuture: Future[Seq[(Int, LibraryTag)]]): Future[Seq[TagStatistics]] = {
    val librariesFuture = librariesService.byPlainLibraryIdentifiers(parsedReports.allDependencies.flatMap(_._1.plainLibraryIdentifiers).toSet)
    val libraryTagAssignmentsFuture = librariesFuture.flatMap{libraries => libraryTagAssignmentsService.forLibraries(libraries.values.map(_._1).toSet)}
    val tagsToLibrariesFuture = libraryTagAssignmentsService.tagsToLibraries(libraryTagAssignmentsFuture)
    val librariesToDependencies = parsedReports.groupedDependenciesByPlainLibraryIdentifier
    for{
      librariesById <- librariesFuture.map(_.values.toMap)
      tagsToLibraries <- tagsToLibrariesFuture
      tags <- tagsFuture
    } yield tags.flatMap{case tagRecord @ (tagId, tag) =>
      val libraryAssignments = tagsToLibraries(tagId)
      val tagLibraries = libraryAssignments.map(a => a.libraryId -> librariesById(a.libraryId))
      val tagDependencies: Set[GroupedDependency] = tagLibraries.flatMap{case (_, lib) => librariesToDependencies(lib.plainLibraryIdentifier)}
      // TODO: vulnerabilities in the past
      if(tagLibraries.isEmpty) None
      else Some(TagStatistics(
        tagRecord = tagRecord,
        stats = LibDepStatistics(
          libraries = tagLibraries,
          dependencies = tagDependencies,
          parsedReports = parsedReports
        )
      ))
    }
  }

  def vulnerabilities(projectOption: Option[String], tagIdOption: Option[Int]) = ReadAction.async {implicit req =>
    val (lastRefreshTime, resultsFuture) = projectReportsProvider.resultsForVersions(versions)
    resultsFuture flatMap { allResults =>
      select(allResults, projectOption).fold(Future.successful(notFound())){ selection =>
        val parsedReports = selection.result
        for{
          libraries <- librariesService.byPlainLibraryIdentifiers(parsedReports.allDependencies.flatMap(_._1.plainLibraryIdentifiers).toSet)
          tagOption <- tagIdOption.fold[Future[Option[(Int, LibraryTag)]]](Future.successful(None))(tagId => tagsService.getById(tagId).map(Some(_)))
          statistics <- tagOption.fold(Future.successful(LibDepStatistics(
            dependencies = parsedReports.groupedDependencies.toSet,
            libraries = libraries.values.toSet,
            parsedReports = parsedReports
          ))){ tag =>
            statisticsForTags(parsedReports, Future.successful(Seq(tag))).map{
              case Seq(TagStatistics(_, stats)) => stats // statisticsForTags is designed for multiple tags, but we have just one…
              case Seq() => LibDepStatistics(libraries = Set(), dependencies = Set(), parsedReports = parsedReports) // We don't want to crash when no dependencies are there…
            }
          }
        } yield Ok(views.html.statistics.vulnerabilities(
          projectsWithSelection = selection.projectsWithSelection,
          tagOption = tagOption,
          statistics = statistics
        ))
      }
    }
  }

  def vulnerability(name: String, selectorOption: Option[String]) = ReadAction.async { implicit req =>
    val ticketOptionFuture = vulnerabilityNotificationService.issueTrackerExport.ticketForVulnerability(name)
    val issueOptionFuture = ticketOptionFuture.map(ticketOption =>
      for{
        ticket <- ticketOption
        issueTrackerService <- issueTrackerServiceOption
      } yield ticket -> issueTrackerService.ticketLink(ticket)
    )
    val (lastRefreshTime, resultsFuture) = projectReportsProvider.resultsForVersions(versions)
    resultsFuture flatMap { allResults =>
      select(allResults, selectorOption).fold(Future.successful(notFound())){ selection =>
        val relevantReports = selection.result
        val vulns = relevantReports.vulnerableDependencies.flatMap(dep => dep.vulnerabilities.map(vuln => (vuln, dep))).groupBy(_._1.name).mapValues{case vulnsWithDeps =>
          val (vulnSeq, depSeq) = vulnsWithDeps.unzip
          //val Seq(vuln) = vulnSeq.toSet.toSeq // Will fail when there are more different descriptions for one vulnerability… TODO: load from database instead
          /*vuln -> */depSeq.toSet
        }// .map(identity) // The .map(identity) materializes lazily mapped Map (because .mapValues is lazy). I am, however, unsure if this is a good idea. Probably not.
        vulns.get(name).fold{
          for{
            vulnOption <- odcService.getVulnerabilityDetails(name)
            issueOption <- issueOptionFuture
          } yield Ok(views.html.statistics.vulnerabilityNotFound( // TODO: the not found page might be replaced by some page explaining that there is no project affected by that vulnerability
            name = name,
            projectsWithSelection = selection.projectsWithSelection,
            failedProjects = selection.result.failedProjects,
            issueOption = issueOption
          ))
        }{ vulnerableDependencies =>
          for {
            vulnOption <- odcService.getVulnerabilityDetails(name)
            plainLibs <- librariesService.byPlainLibraryIdentifiers(vulnerableDependencies.flatMap(_.plainLibraryIdentifiers)).map(_.keySet)
            issueOption <- issueOptionFuture
          } yield vulnOption.fold{
            sys.error("The vulnerability is not in the database, you seem to have outdated the local vulnerability database") // TODO: consider fallback or more friendly error message
          }{vuln => Ok(views.html.statistics.vulnerability(
            vulnerability = vuln,
            failedProjects = selection.result.failedProjects,
            affectedProjects = vulnerableDependencies.flatMap(dep => dep.projects.map(proj => (proj, dep))).groupBy(_._1).mapValues(_.map(_._2)),
            vulnerableDependencies = vulnerableDependencies,
            affectedLibraries = plainLibs,
            projectsWithSelection = selection.projectsWithSelection,
            issueOption = issueOption
          ))}
        }

      }
    }
  }

  implicit val scannedRepositoryFormat = Json.format[ScannedRepository]
  implicit val scannedProjectFormats = Json.format[ScannedProject]

  def table() = ApiAction(ProjectTable).async{
    val RepoFetch = """.*Fetching 'refs/heads/(.*)' from '(.*)'\..*""".r  // Bamboo does not seem to have a suitable API, so we are parsing it from logs…
    val (lastRefreshTime, resultsFuture) = projectReportsProvider.resultsForVersions(versions)
    resultsFuture map { allResults =>
      val t = projects.projectMap
      val rows = t.toIndexedSeq.sortBy(r => (r._2.toLowerCase, r._2)).map{case (key, name) =>
        val repos = allResults._1.get(key).map(_._3.dataString.lines.collect{
          case RepoFetch(branch, repo) => ScannedRepository(repo, branch)
        }.toSet).getOrElse(Set.empty).toIndexedSeq.sortBy(ScannedRepository.unapply)
        ScannedProject(name, repos, projects.teamsByProjectId(key).toIndexedSeq.map(_.name).sorted, key)
      }
      Ok(Json.toJson(rows))
    }
  }

  def allDependencies(selectorOption: Option[String]) = ApiAction(Dependencies).async { implicit req =>
    val (lastRefreshTime, resultsFuture) = projectReportsProvider.resultsForVersions(versions)
    resultsFuture flatMap { allResults =>
      select(allResults, selectorOption).fold(Future.successful(NotFound(Json.obj("error" -> "not found")))){ selection =>
        Future.successful(Ok(Json.toJson(
          selection.result.groupedDependencies.map(gd => GroupedDependencyIdentifier.fromGroupedDependency(gd)).sortBy(gdi => (gdi.identifiers.map(_.name).mkString(", "), gdi.hashes.sha1, gdi.hashes.md5))
        )))
      }
    }
  }

  def allDependenciesVerbose(selectorOption: Option[String]) = ApiAction(Dependencies).async { implicit req =>
    val (lastRefreshTime, resultsFuture) = projectReportsProvider.resultsForVersions(versions)
    resultsFuture flatMap { allResults =>
      select(allResults, selectorOption).fold(Future.successful(NotFound(Json.obj("error" -> "not found")))){ selection =>
        Future.successful(Ok(Json.toJson(
          selection.result.groupedDependencies.map(gd => GroupedDependencyDetailedIdentifier.fromGroupedDependency(gd)).sortBy(gdi => (gdi.identifiers.map(_.name).mkString(", "), gdi.fileNames.mkString(", "), gdi.hashes.sha1, gdi.hashes.md5))
        )))
      }
    }
  }


  def vulnerableLibraries(selectorOption: Option[String]) = ReadAction.async { implicit req =>
    val (lastRefreshTime, resultsFuture) = projectReportsProvider.resultsForVersions(versions)
    resultsFuture flatMap { allResults =>
      select(allResults, selectorOption).fold(Future.successful(notFound())){ selection =>
        val reports = selection.result
        Future.successful(Ok(views.html.statistics.vulnerableLibraries(
          projectsWithSelection = selection.projectsWithSelection,
          vulnerableDependencies = reports.vulnerableDependencies,
          dependenciesWithSuppressedVulnerabilitiesOnlyCount = reports.suppressedOnlyDependencies.size,
          allDependenciesCount = reports.groupedDependencies.size,
          reports = reports
        )))
      }
    }
  }

  def dependencyDetails(selectorOption: Option[String], depPrefix: String, depId: Hashes) = ReadAction.async { implicit req =>
    val (lastRefreshTime, resultsFuture) = projectReportsProvider.resultsForVersions(versions)
    resultsFuture flatMap { allResults =>
      println(selectorOption)
      select(allResults, selectorOption).fold(Future.successful(notFound())) { selection =>
        Future.successful(Ok(views.html.dependencyDetailsInner(
          depPrefix = depPrefix,
          dep = selection.result.groupedDependenciesByHashes(depId),
          selectorOption = selectorOption)
        ).withHeaders("Content-type" -> "text/plain; charset=utf-8"))
      }
    }
  }

  def affectedProjects(depId: Hashes) = ReadAction.async { implicit req =>
    val (lastRefreshTime, resultsFuture) = projectReportsProvider.resultsForVersions(versions)
    resultsFuture flatMap { case (successfulResults, failedResults) =>
      val selection = dependencyCheckReportsParser.parseReports(successfulResults, failedResults)
      Future.successful(Ok(views.html.affectedProjects(
        dep = selection.groupedDependenciesByHashes(depId)
      )).withHeaders("Content-type" -> "text/plain; charset=utf-8"))
    }
  }

  def allFiles(selectorOption: Option[String]) = ReadAction.async { implicit req =>
    val (lastRefreshTime, resultsFuture) = projectReportsProvider.resultsForVersions(versions)
    resultsFuture flatMap { allResults =>
      select(allResults, selectorOption).fold(Future.successful(notFound())){ selection =>
        Future.successful(Ok(Txt(
          selection.result.groupedDependencies.flatMap(_.fileNames.map(_.replace('\\', '/'))).toSet.toIndexedSeq.sorted.mkString("\n")
        )))
      }
    }
  }

  def allLibraries(selectorOption: Option[String]) = ReadAction.async { implicit req =>
    val (lastRefreshTime, resultsFuture) = projectReportsProvider.resultsForVersions(versions)
    resultsFuture flatMap { allResults =>
      select(allResults, selectorOption).fold(Future.successful(notFound())){ selection =>
        Future.successful(Ok(views.html.statistics.allLibraries(
          projectsWithSelection = selection.projectsWithSelection,
          allDependencies = selection.result.groupedDependencies,
          failedProjects = selection.result.failedProjects
        )))
      }
    }
  }

  def allGavs(selectorOption: Option[String]) = ReadAction.async { implicit req =>
    val (lastRefreshTime, resultsFuture) = projectReportsProvider.resultsForVersions(versions)
    resultsFuture flatMap { allResults =>
      select(allResults, selectorOption).fold(Future.successful(notFound())){ selection =>
        Future.successful(Ok(Txt(
          selection.result.groupedDependencies.flatMap(_.mavenIdentifiers).toSet.toIndexedSeq.sortBy((id: Identifier) => (id.identifierType, id.name)).map(id => id.name.split(':') match {
            case Array(g, a, v) =>
              s""""${id.identifierType}", "$g", "$a", "$v", "${id.url}" """
          }).mkString("\n")
        )))
      }
    }
  }


}
