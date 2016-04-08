package modules

import com.google.inject.{AbstractModule, Provides}
import com.typesafe.config.{Config, ConfigObject, ConfigValue}
import com.ysoft.odc.{Absolutizer, CredentialsAtlassianAuthentication}
import net.ceedubs.ficus.Ficus._
import net.ceedubs.ficus.readers.ArbitraryTypeReader._
import net.ceedubs.ficus.readers.ValueReader
import net.codingwell.scalaguice.ScalaModule
import play.api.Configuration
import play.api.libs.json._
import play.api.libs.ws.WSClient
import services.{IssueTrackerService, JiraIssueTrackerService}

import scala.concurrent.ExecutionContext

class IssueTrackerExportModule extends AbstractModule with ScalaModule{

  private implicit object JsonValueReader extends ValueReader[JsObject] {

    implicit def me = this

    import scala.collection.JavaConversions._

    private def extractJson(value: ConfigValue): JsValue = value match {
      case co: ConfigObject => extractJsonFromObject(co)
      case cv: ConfigValue => cv.unwrapped() match {
        case s: String => JsString(s)
        case i: java.lang.Integer => JsNumber(BigDecimal(i))
        case b: java.lang.Boolean => JsBoolean(b)
        //case b: List (ConfigList) => JsArray(b)
      }
    }

    private def extractJsonFromObject(co: ConfigObject): JsObject = JsObject(co.keySet().map{ key => key -> extractJson(co.get(key))}.toMap)

    override def read(config: Config, path: String): JsObject = extractJsonFromObject(config.getObject(path))
  }

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
      val fields = conf.underlying.as[Option[JiraIssueTrackerService.Fields]]("fields").getOrElse(JiraIssueTrackerService.NoFields)
      new JiraIssueTrackerService(
        absolutizer = absolutizer,
        server = conf.underlying.as[String]("server"),
        projectId = conf.underlying.as[Int]("projectId"),
        vulnerabilityIssueType = conf.underlying.as[Int]("vulnerabilityIssueType"),
        atlassianAuthentication = conf.underlying.as[CredentialsAtlassianAuthentication]("authentication"),
        newProjectAddedTransitionNameOption = conf.underlying.as[Option[String]]("newProjectAddedTransitionName"),
        noRelevantProjectAffectedTransitionNameOption = conf.underlying.as[Option[String]]("noRelevantProjectAffectedTransitionName"),
        ticketFormatVersion = conf.underlying.as[Option[Int]]("ticketFormatVersion").getOrElse(1),
        fields = fields
      )
    case other => sys.error("unknown provider for issue tracker: "+other)
  }

}
