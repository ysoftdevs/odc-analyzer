package controllers

import com.github.nscala_time.time.Imports._
import com.google.inject.Inject
import com.google.inject.name.Named
import com.ysoft.odc.Confidence.Confidence
import com.ysoft.odc.statistics.{LibDepStatistics, TagStatistics}
import com.ysoft.odc._
import controllers.DependencyCheckReportsParser.{Result, ResultWithSelection}
import controllers.api.{ApiConfig, ApiController}
import models.LibraryTag
import modules.TemplateCustomization
import org.joda.time.DateTime
import play.api.i18n.MessagesApi
import play.api.libs.json.Json.JsValueWrapper
import play.api.libs.json._
import play.twirl.api.Txt
import services._
import views.html.DefaultRequest

import scala.concurrent.{ExecutionContext, Future}

final case class ScannedRepository(url: String, branch: String)

final case class ScannedProject(name: String, repos: Seq[ScannedRepository], teams: Seq[String], key: String)

final case class GroupedDependencyIdentifier(hashes: Hashes, identifiers: Seq[Identifier])

final case class CompareScanRequest(plan: String, reports: Map[String, String])

object GroupedDependencyIdentifier{
  def fromGroupedDependency(groupedDependency: GroupedDependency): GroupedDependencyIdentifier = GroupedDependencyIdentifier(
    hashes = groupedDependency.hashes,
    identifiers = groupedDependency.identifiersWithFilenames(threshold = Confidence.Highest)
  )
}

final case class CanonizedGroupedDependencyDetailedIdentifier(hashes: Hashes, identifiers: Seq[Identifier], evidence: Seq[Evidence], fileNames: Seq[String]) {
  override def hashCode(): Int = 26+hashes.hashCode()
  override def equals(obj: scala.Any): Boolean = obj match {
    case similar: CanonizedGroupedDependencyDetailedIdentifier => similar.hashes.equals(hashes)
    case _ => false
  }
}

final case class GroupedDependencyDetailedIdentifier(hashes: Hashes, identifiers: Seq[Identifier], evidence: Seq[Evidence], fileNames: Seq[String]) {
  def canonize: CanonizedGroupedDependencyDetailedIdentifier = CanonizedGroupedDependencyDetailedIdentifier(hashes = hashes, identifiers =  identifiers, evidence = evidence, fileNames = fileNames)
}

object GroupedDependencyDetailedIdentifier{
  def fromGroupedDependency(groupedDependency: GroupedDependency) = GroupedDependencyDetailedIdentifier(
    hashes = groupedDependency.hashes,
    identifiers = groupedDependency.identifiers.toIndexedSeq.sortBy(_.name),
    evidence = groupedDependency.evidenceCollected.toIndexedSeq.sortBy(e => (e.name, e.value)),
    fileNames = groupedDependency.fileNames.toIndexedSeq.sortBy(_.toLowerCase)
  )
}

final case class CanonizedGroupedVulnerableDependencyDetailedIdentifier(hashes: Hashes, identifiers: Seq[Identifier], fileNames: Seq[String], vulnerabilities: Seq[String]) {
  override def hashCode(): Int = 52+hashes.hashCode()
  override def equals(obj: scala.Any): Boolean = obj match {
    case same: CanonizedGroupedVulnerableDependencyDetailedIdentifier => hashes.equals(same.hashes)
    case _ => false
  }
}

final case class GroupedVulnerableDependencyDetailedIdentifier(hashes: Hashes, identifiers: Seq[Identifier], fileNames: Seq[String], vulnerabilities: Seq[String]) {
  def canonize: CanonizedGroupedVulnerableDependencyDetailedIdentifier = CanonizedGroupedVulnerableDependencyDetailedIdentifier(hashes = hashes, identifiers = identifiers, fileNames = fileNames, vulnerabilities = vulnerabilities)
}

object GroupedVulnerableDependencyDetailedIdentifier{
  def fromGroupedDependency(groupedDependency: GroupedDependency) = GroupedVulnerableDependencyDetailedIdentifier(
    hashes = groupedDependency.hashes,
    identifiers = groupedDependency.identifiers.toIndexedSeq.sortBy(_.name),
    fileNames = groupedDependency.fileNames.toIndexedSeq.sortBy(_.toLowerCase),
    vulnerabilities = groupedDependency.vulnerabilities.toSeq.map(_.name).sorted
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
  implicit val canonizedGroupedDependencyDetailedIdentifierWrites = Json.writes[CanonizedGroupedDependencyDetailedIdentifier]
  //implicit val groupedDependencyFormats = Json.format[GroupedDependency]
  implicit val groupedVulnerableDependencyDetailedIdentifierWrites = Json.writes[GroupedVulnerableDependencyDetailedIdentifier]
  implicit val canonizedGroupedVulnerableDependencyDetailedIdentifierWrites = Json.writes[CanonizedGroupedVulnerableDependencyDetailedIdentifier]

}

//noinspection TypeAnnotation
class Statistics @Inject()(
  reportsParser: DependencyCheckReportsParser,
  reportsProcessor: DependencyCheckReportsProcessor,
  projectReportsProvider: ProjectReportsProvider,
  dependencyCheckReportsParser: DependencyCheckReportsParser,
  librariesService: LibrariesService,
  tagsService: TagsService,
  odcDbService: OdcDbService,
  odcServiceOption: Option[OdcService],
  libraryTagAssignmentsService: LibraryTagAssignmentsService,
  @Named("missing-GAV-exclusions") missingGAVExclusions: MissingGavExclusions,
  projects: Projects,
  vulnerabilityNotificationService: VulnerabilityNotificationService,
  issueTrackerServiceOption: Option[IssueTrackerService],
  protected val apiConfig: ApiConfig,
  val env: AuthEnv,
  val templateCustomization: TemplateCustomization
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
      val lastDbUpdateFuture = odcDbService.loadLastDbUpdate()
      val isOldFuture = lastDbUpdateFuture.map{ lastUpdate => now - oldDataThreshold > lastUpdate}
      versionOption match {
        case Some(version) =>
          for {
            res1 <- Future.traverse(versionlessCpes) { versionlessCpe => odcDbService.findRelevantCpes(versionlessCpe, version) }
            vulnIds = res1.flatten.map(_.vulnerabilityId).toSet
            vulns <- Future.traverse(vulnIds)(id => odcDbService.getVulnerabilityDetails(id).map(_.get))
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
            vulnOption <- odcDbService.getVulnerabilityDetails(name)
            issueOption <- issueOptionFuture
          } yield vulnOption.fold(
            Ok(views.html.statistics.vulnerabilityNotFound(
              name = name,
              projectsWithSelection = selection.projectsWithSelection,
              failedProjects = selection.result.failedProjects,
              issueOption = issueOption
            ))
          )(vuln => Ok(views.html.statistics.vulnerability(
            projectsWithSelection = selection.projectsWithSelection,
            failedProjects = selection.result.failedProjects,
            issueOption = issueOption,
            vulnerability = vuln,
            affectedProjects = Map(),
            affectedLibraries = Set(),
            vulnerableDependencies = Set()
          )))
        }{ vulnerableDependencies =>
          for {
            vulnOption <- odcDbService.getVulnerabilityDetails(name)
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

  private val RepoFetchLogLine = """.*Fetching 'refs/heads/(.*)' from '(.*)'\..*""".r  // Bamboo does not seem to have a suitable API, so we are parsing it from logs…

  def table() = ApiAction(ProjectTable).async{
    val (lastRefreshTime, resultsFuture) = projectReportsProvider.resultsForVersions(versions)
    resultsFuture map { allResults =>
      val t = projects.projectMap
      val rows = t.toIndexedSeq.sortBy(r => (r._2.toLowerCase, r._2)).map{case (key, name) =>
        val repos: _root_.scala.collection.immutable.IndexedSeq[_root_.controllers.ScannedRepository] = getRepositoryForScan(allResults._1, key)
        ScannedProject(name, repos, projects.teamsByProjectId(key).toIndexedSeq.map(_.name).sorted, key)
      }
      Ok(Json.toJson(rows))
    }
  }

  private def getRepositoryForScan(successfulResults: Map[String, (Build, ArtifactItem, ArtifactFile)], key: String) = {
    val repos = successfulResults.get(key).map(_._3.dataString.lines.collect {
      case RepoFetchLogLine(branch, repo) => ScannedRepository(repo, branch)
    }.toSet).getOrElse(Set.empty).toIndexedSeq.sortBy(ScannedRepository.unapply)
    repos
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
          selectorOption = selectorOption,
          showAffectedProjects = true
        )).withHeaders("Content-type" -> "text/plain; charset=utf-8"))
      }
    }
  }

  def library(selectorOption: Option[String], depId: Hashes) = ReadAction.async { implicit req =>
    val (lastRefreshTime, resultsFuture) = projectReportsProvider.resultsForVersions(versions)
    resultsFuture flatMap { allResults =>
      select(allResults, selectorOption).fold(Future.successful(notFound())) { selection =>
        Future.successful(selection.result.groupedDependenciesByHashes.get(depId) match {
          case None => NotFound(views.html.libraryNotFound(depId = depId, selectorOption = selectorOption))
          case Some(dep) => Ok(views.html.library(dep = dep, selectorOption = selectorOption))
        })
      }
    }
  }

  def libraryVulnerabilities(depId: com.ysoft.odc.Hashes) = ApiAction(ScanResults).async { implicit req =>
    val (lastRefreshTime, resultsFuture) = projectReportsProvider.resultsForVersions(versions)
    resultsFuture flatMap { allResults =>
      select(allResults, None).fold(Future.successful(NotFound(Json.obj("error"->"not found")))) { selection =>
        Future.successful(selection.result.groupedDependenciesByHashes.get(depId) match {
          case None => NotFound(Json.obj("error"->"not found"))
          case Some(dep) => Ok(Json.arr(dep.vulnerabilities.map(_.name).toIndexedSeq.sorted.map(x => x : JsValueWrapper) : _*))
        })
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

  private implicit val compareScanRequestFormats = Json.format[CompareScanRequest]

  def showSet[T: Writes](set: Set[T]) = JsArray(set.toSeq.map(implicitly[Writes[T]].writes))
  def showDiff[T: Writes, A: Writes, R: Writes](diff: SetDiff[T])(mapAdded: T=>A=identity[T] _, mapRemoved: T=>R=identity[T] _) = Json.obj(
    "added" -> showSet(diff.added.map(mapAdded)),
    "removed" -> showSet(diff.removed.map(mapRemoved))
    //"old"->showSet(diff.oldSet),
    //"new"->showSet(diff.newSet)
  )

  def compareScan() = ApiAction(ScanResults).async(parse.json[CompareScanRequest]){ implicit req =>
    val unparsedReports = req.body.reports
    val reportMapFuture = Future {
      unparsedReports.mapValues(OdcParser.parseXmlReport).view.force
    }
    val (lastRefreshTime, resultsFuture) = projectReportsProvider.resultsForVersions(versions)
    resultsFuture flatMap { allResults =>
      select(allResults, Some("project:"+req.body.plan)).fold(Future.successful(NotFound(Json.obj("error"->"not found")))) { selection =>
        if(selection.result.failedProjects.nonEmpty){
          throw new RuntimeException("Cannot compare, because the previous analysis has failed")
        }
        reportMapFuture.map {reportMap =>
          def extractVulnerabilities(r: Result) = {
            r.vulnerableDependencies.flatMap(_.vulnerabilities.map(_.name)).toSet
          }
          val adHocReports = DependencyCheckReportsParser.forAdHocScans(reportMap)
          def compare[T](f: Result => Set[T]) = new SetDiff(f(selection.result), f(adHocReports))
          Ok(Json.obj(
            "vulnerabilities"->showDiff(compare(extractVulnerabilities))(),
            "dependencies"->showDiff(compare(_.groupedDependencies.map(GroupedDependencyDetailedIdentifier.fromGroupedDependency(_).canonize).toSet))(),
            "vulnerableDependencies"->showDiff(compare(_.vulnerableDependencies.map(_.hashes).toSet))(
              // TODO: consider better handling of divergent sets of vulnerabilities
              mapAdded = h => GroupedVulnerableDependencyDetailedIdentifier.fromGroupedDependency(adHocReports.groupedDependenciesByHashes(h)).canonize,
              mapRemoved = h => GroupedVulnerableDependencyDetailedIdentifier.fromGroupedDependency(selection.result.groupedDependenciesByHashes(h)).canonize
            )
          ))
        }
      }
    }
  }


  def librariesCountApi(selector: Option[String], operator: Option[String], threshold: Option[Double], strict: Boolean) = ApiAction(Dependencies).async{ implicit req =>
    val (lastRefreshTime, resultsFuture) = projectReportsProvider.resultsForVersions(versions)
    val vulnLibFilterOrError: Either[GroupedDependency => Boolean, String] = (operator, threshold) match {
      case (Some("gte"|">="|"≥"), Some(num)) => Left(_.vulnerabilities.exists(_.cvssScore.exists(_>=num)))
      case (Some("gt"|">"), Some(num)) => Left(_.vulnerabilities.exists(_.cvssScore.exists(_>num)))
      // Other operators are currently not defined due to unclear semantics when some library has multiple vulnerabilities with various severities
      case (None, None) => Left(_ => true)
      case _ => Right("Bad combination of operator and number. Supported operators are gt and gte or their variants (>, >=, ≥).")
    }
    vulnLibFilterOrError match {
      case Left(vulnLibFilter) =>
        resultsFuture flatMap { allResults =>
          select(allResults, selector).fold(Future.successful(NotFound(Json.obj("error" -> "not found")))) { selection =>
            val reports = selection.result
            if (reports.failedProjects.nonEmpty && strict) {
              Future.successful(InternalServerError(Json.obj("error" -> "I don't have all results I need.")))
            } else {
              Future.successful(Ok(Json.toJson(Map(
                "all" -> reports.groupedDependencies.size,
                "vulnerable" -> reports.vulnerableDependencies.count(vulnLibFilter)
              ))))
            }
          }
        }
      case Right(error) => Future.successful(BadRequest(Json.obj("error" -> error)))
    }
  }

  def internalDependencies(selector: Option[String]) = ApiAction(Dependencies).async {
    val (lastRefreshTime, resultsFuture) = projectReportsProvider.resultsForVersions(versions)
    resultsFuture flatMap { case (successfulResults, failedResults) =>
      val reports = dependencyCheckReportsParser.parseReports(successfulResults, failedResults)
      reports.selection(selector).fold(Future.successful(NotFound(Json.obj("error" -> "not found")))) { selection =>
        val dependenciesByVersionlessIdentifiers = reports.flatReports.groupBy(_._2.groupIdAndArtifactId)
        val allVersionlessIdentifiers = dependenciesByVersionlessIdentifiers.keySet
        val scopedVersionlessIdentifiers = selection.result.groupedDependencies.flatMap(_.mavenIdentifiers).map( x => (x.name+":ignored").split(':') match {
          case Array(groupId, artifactId, version, _) => (groupId, artifactId)
          case other => sys.error("Unexpected array: "+other.toSeq)
        }).toSet
        Future.successful(Ok(Json.toJson(Map(
          "internalMavenDependencies" -> Json.toJson(allVersionlessIdentifiers.intersect(scopedVersionlessIdentifiers).map(id =>
            Map(
              "mavenIdentifier" -> Json.toJson(id match {case (groupId, artifactId) => s"$groupId:$artifactId"}),
              "repositories" -> Json.toJson(dependenciesByVersionlessIdentifiers(id).map(_._1.projectId).flatMap(getRepositoryForScan(successfulResults, _)).toSet)
            )
          ))
        ))))
      }
    }
  }

}

