package services

import javax.inject.Inject

import com.google.inject.name.Named
import com.ysoft.odc.{Absolutizer, AtlassianAuthentication}
import controllers.{Vulnerability, routes}
import models.ExportedVulnerability
import play.api.libs.json.Json.JsValueWrapper
import play.api.libs.json.{JsObject, Json}
import play.api.libs.ws.{WS, WSClient}

import scala.concurrent.{ExecutionContext, Future}

private case class JiraNewIssueResponse(id: String, key: String, self: String)

/**
  * status: WIP
  * It basically works, but there is much to be discussed and implemented.
  */
class JiraIssueTrackerService @Inject() (absolutizer: Absolutizer, @Named("jira-server") server: String, @Named("jira-project-id") projectId: Int, @Named("jira-vulnerability-issue-type") vulnerabilityIssueType: Int, @Named("jira-authentication") atlassianAuthentication: AtlassianAuthentication)(implicit executionContext: ExecutionContext, wSClient: WSClient) extends IssueTrackerService{
  private def jiraUrl(url: String) = atlassianAuthentication.addAuth(WS.clientUrl(url))

  private val formatVersion = 1

  override def reportVulnerability(vulnerability: Vulnerability): Future[ExportedVulnerability[String]] = jiraUrl(server+"/rest/api/2/issue").post(Json.obj(
    "fields" -> (extractInitialFields(vulnerability) ++ extractManagedFields(vulnerability))
  )).map(response => // returns responses like {"id":"1234","key":"PROJ-6","self":"https://…/rest/api/2/issue/1234"}
    try{
      val issueInfo = Json.reads[JiraNewIssueResponse].reads(response.json).get
      ExportedVulnerability(vulnerabilityName = vulnerability.name, ticket = issueInfo.key, ticketFormatVersion = formatVersion)
    }catch{
      case e:Throwable=>sys.error("bad data: "+response.body)
    }
  )

  private def extractInitialFields(vulnerability: Vulnerability): JsObject = Json.obj(
    "project" -> Json.obj(
      "id" -> projectId.toString
    ),
    "summary" -> s"${vulnerability.name} – ${vulnerability.cweOption.map(_ + ": ").getOrElse("")}${vulnerability.description.take(50)}…"
  )

  private def extractManagedFields(vulnerability: Vulnerability): JsObject = Json.obj(
    "issuetype" -> Json.obj(
      "id" -> vulnerabilityIssueType.toString
    ),
    "description" -> extractDescription(vulnerability)
    // TODO: add affected releases
    // TODO: add affected projects
    //"customfield_10100" -> Json.arr("xxxx")
  )

  private def extractDescription(vulnerability: Vulnerability): JsValueWrapper = {
    vulnerability.description + "\n\n" + s"Details: ${absolutizer.absolutize(routes.Statistics.vulnerability(vulnerability.name, None))}"
  }

  override def ticketLink(ticket: String): String = s"$server/browse/$ticket"

}
