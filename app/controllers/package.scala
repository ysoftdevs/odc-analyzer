import com.mohiva.play.silhouette.api.Environment
import com.mohiva.play.silhouette.impl.authenticators.CookieAuthenticator
import models.{SnoozeInfo, User}
import play.api.mvc.Call

/**
 * Created by user on 7/15/15.
 */
package object controllers {

  // Imports for all templates. Those could be added directly to the template files, but IntelliJ IDEA does not like it.
  type Dependency = com.ysoft.odc.Dependency
  type Build = com.ysoft.odc.Build
  type GroupedDependency = com.ysoft.odc.GroupedDependency
  type Vulnerability = com.ysoft.odc.Vulnerability
  type Identifier = com.ysoft.odc.Identifier
  type DateTime = org.joda.time.DateTime
  type SnoozesInfo = Map[String, SnoozeInfo]
  type AuthEnv = Environment[User, CookieAuthenticator]
  type LibDepStatistics = com.ysoft.odc.statistics.LibDepStatistics


  val NormalUrlPattern = """^(http(s?)|ftp(s?))://.*""".r

  val TooGenericDomains = Set("sourceforge.net", "github.com", "github.io")


/*  def friendlyProjectName(unfriendlyName: String) = {
    val (baseName, theRest) = unfriendlyName.span(_ != '/')
    //theRest.drop(1)
    val removeLeadingMess = RestMessBeginRegexp.replaceAllIn(_: String, "")
    val removeTrailingMess = RestMessEndRegexp.replaceAllIn(_: String, "")
    val removeMess = removeLeadingMess andThen removeTrailingMess
    val subProjectOption = Some(removeMess(theRest)).filter(_ != "")
    subProjectOption.fold(baseName)(baseName+"/"+_)
  }*/
  def friendlyProjectNameString(reportInfo: ReportInfo) = reportInfo.subprojectNameOption.fold(reportInfo.projectName)(reportInfo.projectName+": "+_)

  val severityOrdering: Ordering[GroupedDependency] = Ordering.by((d: GroupedDependency) => (
    d.maxCvssScore.map(-_).getOrElse(0.0),                                          // maximum CVSS score is the king
    if(d.maxCvssScore.isEmpty) Some(-d.dependencies.size) else None,                // more affected dependencies if no vulnerability has defined severity
    -d.vulnerabilities.size,                                                        // more vulnerabilities
    -d.projects.size,                                                               // more affected projects
    d.cpeIdentifiers.map(_.toCpeIdentifierOption.get).toSeq.sorted.mkString(" "))   // at least make the order deterministic
  )

  def vulnerableSoftwareSearches(groupedDependency: GroupedDependency): Seq[(Call, String)] = {
    val legacySearchOption = groupedDependency.cpeIdentifiers match {
      case Seq() => None
      case cpeIds => Some(
        routes.Statistics.searchVulnerableSoftware(
          cpeIds.map(_.name.split(':').take(4).mkString(":")).toSeq, None
        ) -> "Search by CPE (legacy option)"
      )
    }
    val mavenSearches = groupedDependency.mavenIdentifiers.map(_.name).toSeq.sorted.map{mavenIdentifier =>
      val Array(groupId, artifactId, version) = mavenIdentifier.split(":", 3)
      val identifierString = <dependency><groupId>{groupId}</groupId><artifactId>{artifactId}</artifactId><version>{version}</version></dependency>.toString()
      routes.LibraryAdvisor.index(Some(identifierString)) -> s"Look for Maven dependency $mavenIdentifier"
    }
    mavenSearches ++ legacySearchOption

  }

}
