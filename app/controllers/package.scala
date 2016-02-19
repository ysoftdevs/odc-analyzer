import com.mohiva.play.silhouette.api.Environment
import com.mohiva.play.silhouette.impl.authenticators.CookieAuthenticator
import models.{User, SnoozeInfo}

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

}
