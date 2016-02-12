package modules

import com.google.inject.{AbstractModule, Provides}
import com.ysoft.odc.{Absolutizer, CredentialsAtlassianAuthentication}
import net.ceedubs.ficus.Ficus._
import net.ceedubs.ficus.readers.ArbitraryTypeReader._
import net.codingwell.scalaguice.ScalaModule
import play.api.Configuration
import play.api.libs.ws.WSClient
import services.{IssueTrackerService, JiraIssueTrackerService}

import scala.concurrent.ExecutionContext

class IssueTrackerExportModule extends AbstractModule with ScalaModule{
  override def configure(): Unit = {
  }

  @Provides
  def provideIssueTrackerOption(conf: Configuration, absolutizer: Absolutizer)(implicit executionContext: ExecutionContext, wSClient: WSClient): Option[IssueTrackerService] = {
    conf.getConfig("yssdc.export.issueTracker").map(issueTrackerConfiguration(absolutizer))
  }

  private def issueTrackerConfiguration(absolutizer: Absolutizer)(conf: Configuration)(implicit executionContext: ExecutionContext, wSClient: WSClient): IssueTrackerService = conf.getString("provider") match{
    case Some("jira") =>
      conf.getString("authentication.type") match {
        case Some("credentials") =>
        case other => sys.error("unknown authentication type: "+other)
      }
      new JiraIssueTrackerService(
        absolutizer = absolutizer,
        server = conf.underlying.as[String]("server"),
        projectId = conf.underlying.as[Int]("projectId"),
        vulnerabilityIssueType = conf.underlying.as[Int]("vulnerabilityIssueType"),
        atlassianAuthentication = conf.underlying.as[CredentialsAtlassianAuthentication]("authentication")
      )
    case other => sys.error("unknown provider for issue tracker: "+other)
  }

}
