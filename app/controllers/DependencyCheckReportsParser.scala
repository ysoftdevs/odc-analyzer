package controllers

import java.net.URLEncoder

import com.google.inject.Inject
import com.ysoft.odc._
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
}
private final case class ProjectFilter(project: ReportInfo) extends Filter{
  override def filters: Boolean = true
  override def descriptionHtml: Html = views.html.filters.project(project)
  override def descriptionText: String = s"project ${friendlyProjectName(project)}"
  override def subReports(r: Result): Option[Result] = {
    @inline def reportInfo = project
    def f[T](m: Map[ReportInfo, T]): Map[String, T] = (
      if(reportInfo.subprojectNameOption.isEmpty) m.filter(_._1.projectId == project.projectId) else m.get(reportInfo).fold(Map.empty[ReportInfo, T])(x => Map(reportInfo -> x))
    ).map{case (k, v) => k.fullId -> v}
    val newFlatReports = f(r.flatReports)
    val newFailedAnalysises = f(r.failedAnalysises)
    if(newFlatReports.isEmpty && newFailedAnalysises.isEmpty) None
    else Some(Result(bareFlatReports = newFlatReports, bareFailedAnalysises = newFailedAnalysises, projects = r.projects))
  }
  override def selector = Some(s"project:${project.fullId}")
}
private final case class TeamFilter(team: Team) extends Filter{
  override def filters: Boolean = true
  override def subReports(r: Result): Option[Result] = {
    val Wildcard = """^(.*): \*$""".r
    val reportInfoByFriendlyProjectNameMap = r.projectsReportInfo.ungroupedReportsInfo.map(ri => friendlyProjectName(ri) -> ri).toSeq.groupBy(_._1).mapValues{
      case Seq((_, ri)) => ri
      case other => sys.error("some duplicate value: "+other)
    }.map(identity)
    val ProjectName = """^(.*): (.*)$""".r
    val rootProjectReports = reportInfoByFriendlyProjectNameMap.collect{case (ProjectName(rootProject, subproject), v) => (rootProject, v)}.groupBy(_._1).mapValues(_.map(_._2))
    def reportInfoByFriendlyProjectName(fpn: String) = reportInfoByFriendlyProjectNameMap.get(fpn).map(Set(_)).getOrElse(rootProjectReports(fpn.takeWhile(_ != ':')))
    val reportInfos = team.projectNames.flatMap(reportInfoByFriendlyProjectName)
    def submap[T](m: Map[String, T]) = reportInfos.toSeq.flatMap(ri => m.get(ri.fullId).map(ri.fullId -> _) ).toMap
    Some(Result(
      bareFlatReports = submap(r.bareFlatReports),
      bareFailedAnalysises = submap(r.bareFailedAnalysises),
      projects = r.projects
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
}
private final case class BadFilter(pattern: String) extends Filter{
  override def filters: Boolean = true
  override def subReports(r: Result): Option[Result] = None
  override def descriptionHtml: Html = Html("<b>bad filter</b>")
  override def descriptionText: String = "bad filter"
  override def selector: Option[String] = Some(pattern)
}

object DependencyCheckReportsParser{
  final case class ResultWithSelection(result: Result, projectsWithSelection: ProjectsWithSelection)
  final case class Result(bareFlatReports: Map[String, Analysis], bareFailedAnalysises: Map[String, Throwable], projects: Projects){
    lazy val projectsReportInfo = new ProjectsWithReports(projects, bareFlatReports.keySet ++ bareFailedAnalysises.keySet)
    lazy val flatReports: Map[ReportInfo, Analysis] = bareFlatReports.map{case (k, v) => projectsReportInfo.reportIdToReportInfo(k) -> v}
    lazy val failedAnalysises: Map[ReportInfo, Throwable] = bareFailedAnalysises.map{case (k, v) => projectsReportInfo.reportIdToReportInfo(k) -> v}
    lazy val allDependencies = flatReports.toSeq.flatMap(r => r._2.dependencies.map(_ -> r._1))
    lazy val groupedDependencies = allDependencies.groupBy(_._1.hashes).values.map(GroupedDependency(_)).toSeq
    lazy val groupedDependenciesByPlainLibraryIdentifier: Map[PlainLibraryIdentifier, Set[GroupedDependency]] =
      groupedDependencies.toSet.flatMap((grDep: GroupedDependency) => grDep.plainLibraryIdentifiers.map(_ -> grDep)).groupBy(_._1).mapValues(_.map(_._2)).map(identity)
    lazy val vulnerableDependencies = groupedDependencies.filter(_.vulnerabilities.nonEmpty)

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

  def parseReports(successfulResults: Map[String, (Build, ArtifactItem, ArtifactFile)]) = {
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
    Result(flatReports, failedAnalysises, projects)
  }

}
