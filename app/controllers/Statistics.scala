package controllers

import com.github.nscala_time.time.Imports._
import com.google.inject.Inject
import com.google.inject.name.Named
import com.ysoft.odc.{ArtifactFile, ArtifactItem}
import models.{Library, LibraryTag}
import org.joda.time.DateTime
import play.api.i18n.MessagesApi
import play.twirl.api.Txt
import services._
import views.html.DefaultRequest

import scala.concurrent.{ExecutionContext, Future}

object Statistics{
  case class LibDepStatistics(libraries: Set[(Int, Library)], dependencies: Set[GroupedDependency]){
    def vulnerableRatio = vulnerableDependencies.size.toDouble / dependencies.size.toDouble
    lazy val vulnerabilities: Set[Vulnerability] = dependencies.flatMap(_.vulnerabilities)
    lazy val vulnerabilitiesByName = vulnerabilities.map(v => v.name -> v).toMap
    lazy val vulnerabilityNames = vulnerabilities.map(_.name)
    lazy val vulnerabilitiesToDependencies: Map[Vulnerability, Set[GroupedDependency]] = vulnerableDependencies.flatMap(dep =>
      dep.vulnerabilities.map(vuln => (vuln, dep))
    ).groupBy(_._1).mapValues(_.map(_._2)).map(identity)
    vulnerableDependencies.flatMap(dep => dep.vulnerabilities.map(_ -> dep)).groupBy(_._1).mapValues(_.map(_._2)).map(identity)
    vulnerableDependencies.flatMap(dep => dep.vulnerabilities.map(_ -> dep)).groupBy(_._1).mapValues(_.map(_._2)).map(identity)
    lazy val vulnerableDependencies = dependencies.filter(_.isVulnerable)
    lazy val (dependenciesWithCpe, dependenciesWithoutCpe) = dependencies.partition(_.hasCpe)
    lazy val cpeRatio = dependenciesWithCpe.size.toDouble / dependencies.size.toDouble
    lazy val weaknesses = vulnerabilities.flatMap(_.cweOption)
    lazy val weaknessesFrequency = computeWeaknessesFrequency(vulnerabilities)
  }
  case class TagStatistics(tagRecord: (Int, LibraryTag), stats: LibDepStatistics){
    def tag: LibraryTag = tagRecord._2
    def tagId: Int = tagRecord._1
  }

  def computeWeaknessesFrequency(vulnerabilities: Set[Vulnerability]) = vulnerabilities.toSeq.map(_.cweOption).groupBy(identity).mapValues(_.size).map(identity).withDefaultValue(0)

}

import controllers.Statistics._

class Statistics @Inject() (
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
  val env: AuthEnv
)(implicit val messagesApi: MessagesApi, executionContext: ExecutionContext) extends AuthenticatedController {

  private val versions = Map[String, Int]()

  private def notFound()(implicit req: DefaultRequest) = {
    NotFound(views.html.defaultpages.notFound("GET", req.uri))
  }

  import secureRequestConversion._


  private def select(successfulResults: Map[String, (Build, ArtifactItem, ArtifactFile)], selectorOption: Option[String]) = dependencyCheckReportsParser.parseReports(successfulResults).selection(selectorOption)

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

  def basic(projectOption: Option[String]) = ReadAction.async{ implicit req =>
    val (lastRefreshTime, resultsFuture) = projectReportsProvider.resultsForVersions(versions)
    resultsFuture flatMap { case (successfulResults, failedResults) =>
      select(successfulResults, projectOption).fold(Future.successful(notFound())){ selection =>
        val tagsFuture = tagsService.all
        val parsedReports = selection.result
        for{
          tagStatistics <- statisticsForTags(parsedReports, tagsFuture)
        } yield Ok(views.html.statistics.basic(
          tagStatistics = tagStatistics,
          projectsWithSelection = selection.projectsWithSelection,
          parsedReports = parsedReports
        ))
      }
    }
  }

  def statisticsForTags(parsedReports: DependencyCheckReportsParser.Result, tagsFuture: Future[Seq[(Int, LibraryTag)]]): Future[Seq[Statistics.TagStatistics]] = {
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
      else Some(TagStatistics(tagRecord = tagRecord, stats = LibDepStatistics(libraries = tagLibraries, dependencies = tagDependencies)))
    }
  }

  def vulnerabilities(projectOption: Option[String], tagIdOption: Option[Int]) = ReadAction.async {implicit req =>
    val (lastRefreshTime, resultsFuture) = projectReportsProvider.resultsForVersions(versions)
    resultsFuture flatMap { case (successfulResults, failedResults) =>
      select(successfulResults, projectOption).fold(Future.successful(notFound())){ selection =>
        val parsedReports = selection.result
        for{
          libraries <- librariesService.byPlainLibraryIdentifiers(parsedReports.allDependencies.flatMap(_._1.plainLibraryIdentifiers).toSet)
          tagOption <- tagIdOption.fold[Future[Option[(Int, LibraryTag)]]](Future.successful(None))(tagId => tagsService.getById(tagId).map(Some(_)))
          statistics <- tagOption.fold(Future.successful(LibDepStatistics(dependencies = parsedReports.groupedDependencies.toSet, libraries = libraries.values.toSet))){ tag =>
            statisticsForTags(parsedReports, Future.successful(Seq(tag))).map{
              case Seq(TagStatistics(_, stats)) => stats // statisticsForTags is designed for multiple tags, but we have just one…
              case Seq() => LibDepStatistics(libraries = Set(), dependencies = Set()) // We don't want to crash when no dependencies are there…
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

  def vulnerability(name: String, projectOption: Option[String]) = ReadAction.async { implicit req =>
    val (lastRefreshTime, resultsFuture) = projectReportsProvider.resultsForVersions(versions)
    resultsFuture flatMap { case (successfulResults, failedResults) =>
      select(successfulResults, projectOption).fold(Future.successful(notFound())){ selection =>
        val relevantReports = selection.result
        val vulns = relevantReports.vulnerableDependencies.flatMap(dep => dep.vulnerabilities.map(vuln => (vuln, dep))).groupBy(_._1.name).mapValues{case vulnsWithDeps =>
          val (vulnSeq, depSeq) = vulnsWithDeps.unzip
          //val Seq(vuln) = vulnSeq.toSet.toSeq // Will fail when there are more different descriptions for one vulnerability… TODO: load from database instead
          /*vuln -> */depSeq.toSet
        }// .map(identity) // The .map(identity) materializes lazily mapped Map (because .mapValues is lazy). I am, however, unsure if this is a good idea. Probably not.
        vulns.get(name).fold{
          for{
            vulnOption <- odcService.getVulnerabilityDetails(name)
          } yield Ok(views.html.statistics.vulnerabilityNotFound( // TODO: the not found page might be replaced by some page explaining that there is no project affected by that vulnerability
            name = name,
            projectsWithSelection = selection.projectsWithSelection
          ))
        }{ vulnerableDependencies =>
          for {
            vulnOption <- odcService.getVulnerabilityDetails(name)
            plainLibs <- librariesService.byPlainLibraryIdentifiers(vulnerableDependencies.flatMap(_.plainLibraryIdentifiers)).map(_.keySet)
            ticketOption <- vulnerabilityNotificationService.issueTrackerExport.ticketForVulnerability(name)
          } yield vulnOption.fold{
            sys.error("The vulnerability is not in the database, you seem to have outdated the local vulnerability database") // TODO: consider fallback or more friendly error message
          }{vuln => Ok(views.html.statistics.vulnerability(
            vulnerability = vuln,
            affectedProjects = vulnerableDependencies.flatMap(dep => dep.projects.map(proj => (proj, dep))).groupBy(_._1).mapValues(_.map(_._2)),
            vulnerableDependencies = vulnerableDependencies,
            affectedLibraries = plainLibs,
            projectsWithSelection = selection.projectsWithSelection,
            issueOption = for{
              ticket <- ticketOption
              issueTrackerService <- issueTrackerServiceOption
            } yield ticket -> issueTrackerService.ticketLink(ticket)
          ))}
        }

      }
    }
  }

  def vulnerableLibraries(project: Option[String]) = ReadAction.async { implicit req =>
    val (lastRefreshTime, resultsFuture) = projectReportsProvider.resultsForVersions(versions)
    resultsFuture flatMap { case (successfulResults, failedResults) =>
      select(successfulResults, project).fold(Future.successful(notFound())){selection =>
        val reports = selection.result
        Future.successful(Ok(views.html.statistics.vulnerableLibraries(
          projectsWithSelection = selection.projectsWithSelection,
          vulnerableDependencies = reports.vulnerableDependencies,
          allDependenciesCount = reports.groupedDependencies.size
        )))
      }
    }
  }

  def allLibraries(project: Option[String]) = ReadAction.async { implicit req =>
    val (lastRefreshTime, resultsFuture) = projectReportsProvider.resultsForVersions(versions)
    resultsFuture flatMap { case (successfulResults, failedResults) =>
      select(successfulResults, project).fold(Future.successful(notFound())){selection =>
        Future.successful(Ok(views.html.statistics.allLibraries(
          projectsWithSelection = selection.projectsWithSelection,
          allDependencies = selection.result.groupedDependencies
        )))
      }
    }
  }

  def allGavs(project: Option[String]) = ReadAction.async { implicit req =>
    val (lastRefreshTime, resultsFuture) = projectReportsProvider.resultsForVersions(versions)
    resultsFuture flatMap { case (successfulResults, failedResults) =>
      select(successfulResults, project).fold(Future.successful(notFound())){selection =>
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
