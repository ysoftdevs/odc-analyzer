package controllers

final case class ReportInfo(
  projectId: String,
  projectName: String,
  fullId: String,
  subprojectNameOption: Option[String]
) extends Ordered[ReportInfo] {

  import scala.math.Ordered.orderingToOrdered

  //noinspection ScalaUnnecessaryParentheses
  override def compare(that: ReportInfo): Int = ((projectName, subprojectNameOption, fullId)) compare ((that.projectName, that.subprojectNameOption, that.fullId))

  // It seems to be a good idea to have a custom equals and hashCode for performance reasons


  override def equals(other: Any): Boolean = other match {
    case other: ReportInfo => fullId == other.fullId
    case _ => false
  }

  override def hashCode(): Int = 517+fullId.hashCode

  def bare = copy(subprojectNameOption = None, fullId = fullId.takeWhile(_ != '/'))

}

object ProjectsWithReports{

  private val RestMessBeginRegexp = """^/Report results-XML(/|$)""".r

  private val RestMessEndRegexp = """(/|^)(target/)?dependency-check-report\.xml$""".r

}

class ProjectsWithReports (val projects: Projects, val reports: Set[String]) {

  import ProjectsWithReports._

  val reportIdToReportInfo = {
    val reportsMap = reports.map{ unfriendlyName =>
      unfriendlyName -> parseUnfriendlyName(unfriendlyName)
    }.toMap
    reportsMap ++ reportsMap.values.map(r => r.projectId -> ReportInfo(projectId = r.projectId, fullId = r.projectId, subprojectNameOption = None, projectName = r.projectName))
  }

  def parseUnfriendlyName(unfriendlyName: String): ReportInfo = {
    val (baseName, theRest) = unfriendlyName.span(_ != '/')
    val removeLeadingMess = RestMessBeginRegexp.replaceAllIn(_: String, "")
    val removeTrailingMess = RestMessEndRegexp.replaceAllIn(_: String, "")
    val removeMess = removeLeadingMess andThen removeTrailingMess
    val subProjectOption = Some(removeMess(theRest)).filter(_ != "")
    ReportInfo(
      projectId = baseName,
      fullId = unfriendlyName,
      projectName = projects.projectMap(baseName),
      subprojectNameOption = subProjectOption.orElse(Some("root project"))
    )
  }

  val ungroupedReportsInfo = reportIdToReportInfo.values.toSet

  def sortedReportsInfo = ungroupedReportsInfo.toSeq.sortBy(p => p.projectName -> p.projectId -> p.subprojectNameOption)

}
