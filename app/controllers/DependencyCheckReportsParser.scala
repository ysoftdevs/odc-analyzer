package controllers

import java.net.URLEncoder

import com.google.inject.Inject
import com.ysoft.odc._
import com.ysoft.odc.statistics.FailedProjects
import controllers.DependencyCheckReportsParser.Result
import models.PlainLibraryIdentifier
import play.api.Logger
import play.api.cache.CacheApi
import play.twirl.api.Html

import scala.util.{Failure, Success, Try}

sealed trait Filter{
  def selector: Option[String]
  def subReports(r: Result): Option[Result]
  def filters: Boolean
  def descriptionHtml: Html
  def descriptionText: String
  def filterProjectsWithReports(projectsWithReports: ProjectsWithReports): Option[ProjectsWithReports] = ???
}
final case class ProjectFilter(project: ReportInfo) extends Filter{
  override def filters: Boolean = true
  override def descriptionHtml: Html = views.html.filters.project(project)
  override def descriptionText: String = s"project ${friendlyProjectNameString(project)}"
  override def subReports(r: Result): Option[Result] = {
    @inline def reportInfo = project
    def filter[T](m: Map[ReportInfo, T]): Map[ReportInfo, T] = (
      if(reportInfo.subprojectNameOption.isEmpty) m.filter(_._1.projectId == project.projectId)
      else m.get(reportInfo).fold(Map.empty[ReportInfo, T])(x => Map(reportInfo -> x))
    )
    val newFlatReports = filter(r.flatReports)
    val newFailedAnalysises = filter(r.failedAnalysises)
    val newFailedReportDownloads = filter(r.failedReportDownloads)
    if(newFlatReports.isEmpty && newFailedAnalysises.isEmpty && newFailedReportDownloads.isEmpty) None
    else Some(Result(
      bareFlatReports = newFlatReports,
      bareFailedAnalysises = newFailedAnalysises,
      projectsReportInfo = r.projectsReportInfo,
      failedReportDownloads = newFailedReportDownloads
    ))
  }
  override def selector = Some(s"project:${project.fullId}")
}
final case class TeamFilter(team: Team) extends Filter{
  override def filters: Boolean = true

  private def splitSuccessesAndFailures[T, U](set: Set[Either[T, U]]) = {
    val (lefts, rights) = set.partition(_.isLeft)
    (
      lefts.map(_.asInstanceOf[Left[T, U]].a),
      rights.map(_.asInstanceOf[Right[T, U]].b)
    )
  }

  override def subReports(r: Result): Option[Result] = {
    val Wildcard = """^(.*): \*$""".r
    @inline def toMapStrict[K, V](l: Traversable[(K, V)]) = l.toSeq.groupBy(_._1).mapValues{  // without toSeq, the pattern matching might fail
      case Seq((_, v)) => v
      case other => sys.error("some duplicate value: "+other)
    }.map(identity)
    val reportInfoByFriendlyProjectNameMap = toMapStrict(r.projectsReportInfo.ungroupedReportsInfo.map(ri => friendlyProjectNameString(ri) -> ri))
    val ProjectName = """^(.*): (.*)$""".r
    val failedProjectsFriendlyNames = r.failedProjects.failedProjectsSet.map(_.projectName)
    val rootProjectReports = reportInfoByFriendlyProjectNameMap.groupBy{
      case (ProjectName(rootProject, _subproject), v) => rootProject
      case (rootProject, v) => rootProject
    }.mapValues(_.values).map(identity).withDefault(name =>
      if(failedProjectsFriendlyNames contains name) Seq()
      else sys.error("Unknown project: "+name)
    )
    def reportInfoByFriendlyProjectName(fpn: String): Either[Iterable[ReportInfo], String] = {
      def toEither[T](v: Option[T]): Either[T, String] = v.fold[Either[T, String]](Right(fpn))(Left(_))
      fpn match{
        case Wildcard(rfpn) => toEither(rootProjectReports.get(rfpn))
        case _ => toEither(reportInfoByFriendlyProjectNameMap.get(fpn).map(Set(_)))
      }
    }
    val (reportInfosDeep, projectsNotFound) = splitSuccessesAndFailures(team.projectNames.map(reportInfoByFriendlyProjectName))
    val reportInfos: Set[ReportInfo] = reportInfosDeep.flatten
    def submap[T](m: Map[ReportInfo, T]) = reportInfos.toSeq.flatMap(ri => m.get(ri).map(ri -> _) ).toMap
    def submapBare[T](m: Map[ReportInfo, T]): Map[ReportInfo, T] = reportInfos.toSeq.flatMap(ri => m.get(ri.bare).map(ri -> _) ).toMap
    // TODO: projectsNotFoundMap is a hack for reporting errors to humans, because there is no suitable category for such errors
    val projectsNotFoundMap = projectsNotFound.map(name => ReportInfo("name: " + name, name, "name: " + name, None) -> new RuntimeException("Project " + name + " not found")).toMap
    Some(Result(
      bareFlatReports = submap(r.bareFlatReports),
      bareFailedAnalysises = submapBare(r.bareFailedAnalysises) ++ projectsNotFoundMap,
      projectsReportInfo = r.projectsReportInfo,
      failedReportDownloads = submapBare(r.failedReportDownloads)
    ))
  }
  override def descriptionHtml: Html = views.html.filters.team(team.id)
  override def descriptionText: String = s"team ${team.name}"
  override def selector = Some(s"team:${team.id}")
}
object NoFilter extends Filter{
  override def filters: Boolean = false
  override val descriptionHtml: Html = views.html.filters.all()
  override def descriptionText: String = "all projects"
  override def subReports(r: Result): Option[Result] = Some(r)
  override def selector: Option[String] = None
  override def filterProjectsWithReports(projectsWithReports: ProjectsWithReports): Option[ProjectsWithReports] = Some(projectsWithReports)
}
private final case class BadFilter(pattern: String) extends Filter{
  override def filters: Boolean = true
  override def subReports(r: Result): Option[Result] = None
  override def descriptionHtml: Html = Html("<b>bad filter</b>")
  override def descriptionText: String = "bad filter"
  override def selector: Option[String] = Some(pattern)
  override def filterProjectsWithReports(projectsWithReports: ProjectsWithReports): Option[ProjectsWithReports] = None
}

object DependencyCheckReportsParser{
  def forAdHocScan(analysis: Analysis): Result = Result(Map(ReportInfo("adHocScan", "Ad hoc scan", "AHS", None) -> analysis), Map(), new ProjectsWithReports(new Projects(Map(), Map(), Map()), Set()), Map())
  def forAdHocScans(analysises: Map[String, Analysis]): Result = Result(
    bareFlatReports = analysises.map{case (key, analysis) => ReportInfo("adHocScan", "Ad hoc scan", "AHS:"+key, Some(key)) -> analysis},
    bareFailedAnalysises = Map(),
    projectsReportInfo = new ProjectsWithReports(new Projects(Map(), Map(), Map()), Set()),
    failedReportDownloads = Map()
  )
  final case class ResultWithSelection(result: Result, projectsWithSelection: ProjectsWithSelection)
  final case class Result(bareFlatReports: Map[ReportInfo, Analysis], bareFailedAnalysises: Map[ReportInfo, Throwable], projectsReportInfo: ProjectsWithReports/*TODO: maybe rename to rootProjects*/, failedReportDownloads: Map[ReportInfo, Throwable]){
    //lazy val projectsReportInfo = new ProjectsWithReports(projects, (bareFlatReports.keySet ++ bareFailedAnalysises.keySet ++ failedReportDownloads.keySet).map(_.fullId)) // TODO: consider renaming to projectsWithReports
    @inline def flatReports: Map[ReportInfo, Analysis] = bareFlatReports // TODO: unify
    @inline def projects = projectsReportInfo.projects
    @inline def failedAnalysises: Map[ReportInfo, Throwable] = bareFailedAnalysises // TODO: unify
    lazy val failedProjects = FailedProjects.combineFails(parsingFailures = failedAnalysises, failedReportDownloads = failedReportDownloads)
    lazy val allDependencies = flatReports.toSeq.flatMap(r => r._2.dependencies.map(_ -> r._1))
    lazy val groupedDependencies = allDependencies.groupBy(_._1.hashes).values.map(GroupedDependency(_)).toSeq
    lazy val groupedDependenciesByPlainLibraryIdentifier: Map[PlainLibraryIdentifier, Set[GroupedDependency]] =
      groupedDependencies.toSet.flatMap((grDep: GroupedDependency) => grDep.plainLibraryIdentifiers.map(_ -> grDep)).groupBy(_._1).mapValues(_.map(_._2)).map(identity)
    lazy val groupedDependenciesByHashes: Map[Hashes, GroupedDependency] = groupedDependencies.map(gd => gd.hashes -> gd).toMap
    lazy val vulnerableDependencies = groupedDependencies.filter(_.vulnerabilities.nonEmpty)
    lazy val nonVulnerableDependencies = groupedDependencies.filter(_.vulnerabilities.isEmpty)
    lazy val suppressedOnlyDependencies = groupedDependencies.filter(gd => gd.vulnerabilities.isEmpty && gd.suppressedIdentifiers.nonEmpty)

    private val ProjectSelectorPattern = """^project:(.*)$""".r
    private val TeamSelectorPattern = """^team:(.*)$""".r

    private def parseFilter(filter: String): Filter = filter match {
      case ProjectSelectorPattern(project) => ProjectFilter(projectsReportInfo.reportIdToReportInfo(project))
      case TeamSelectorPattern(team) => TeamFilter(projects.teamById(team))
      case other => BadFilter(other)
    }

    def selection(selectorOption: Option[String]): Option[ResultWithSelection] = {
      val filter = selectorOption.map(parseFilter).getOrElse(NoFilter)
      filter.subReports(this).map{ result =>
        ResultWithSelection(
          result = result,
          projectsWithSelection = ProjectsWithSelection(filter = filter, projectsWithReports = projectsReportInfo, teams = projects.teamSet)
        )
      }
    }

  }
}

final class DependencyCheckReportsParser @Inject() (cache: CacheApi, projects: Projects) {

  def parseReports(successfulResults: Map[String, (Build, ArtifactItem, ArtifactFile)], failedReportDownloads: Map[String, Throwable]): Result = {
    val rid = math.random.toString  // for logging
    @volatile var parseFailedForSomeAnalysis = false
    val deepReportsTriesIterable: Iterable[Map[String, Try[Analysis]]] = for((k, (build, data, log)) <- successfulResults) yield {
      Logger.debug(data.flatFilesWithPrefix(s"$k/").keySet.toSeq.sorted.toString)
      val flat = data.flatFilesWithPrefix(s"$k/")
      (for((k, v) <- flat.par) yield {
        val analysisKey = URLEncoder.encode(s"analysis/parsedXml/${build.buildResultKey}/${k}", "utf-8")
        Logger.debug(s"[$rid] analysisKey: $analysisKey")
        val analysisTry = cache.getOrElse(analysisKey)(Try{OdcParser.parseXmlReport(v)})
        analysisTry match{
          case Success(e) => // nothing
          case Failure(e) =>
            if(!parseFailedForSomeAnalysis){
              Logger.error(s"[$rid] Cannot parse $k: ${new String(v, "utf-8")}", e)
              parseFailedForSomeAnalysis = true
            }
        }
        k -> analysisTry
      }).seq
    }
    val deepReportsAndFailuresIterable = deepReportsTriesIterable.map { reports =>
      val (successfulReportsTries, failedReportsTries) = reports.partition(_._2.isSuccess)
      val successfulReports = successfulReportsTries.mapValues(_.asInstanceOf[Success[Analysis]].value).map(identity)
      val failedReports = failedReportsTries.mapValues(_.asInstanceOf[Failure[Analysis]].exception).map(identity)
      (successfulReports, failedReports)
    }
    val deepSuccessfulReports = deepReportsAndFailuresIterable.map(_._1).toSeq
    val failedAnalysises = deepReportsAndFailuresIterable.map(_._2).toSeq.flatten.toMap
    val flatReports = deepSuccessfulReports.flatten.toMap
    Logger.debug(s"[$rid] parse finished")
    val projectReportInfo = new ProjectsWithReports(projects, flatReports.keySet++failedAnalysises.keySet++failedReportDownloads.keySet)
    def convertKeys[T](m: Map[String, T]) = m.map{case (k, v) => projectReportInfo.reportIdToReportInfo(k) -> v}
    Result(
      convertKeys(flatReports),
      convertKeys(failedAnalysises),
      projectReportInfo,
      failedReportDownloads = convertKeys(failedReportDownloads)
    )
  }

}
