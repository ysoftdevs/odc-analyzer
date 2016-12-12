package services

import javax.inject.Inject

import com.google.inject.name.Named
import com.ysoft.odc.{Absolutizer, AtlassianAuthentication, SetDiff}
import controllers.{ReportInfo, Vulnerability, friendlyProjectNameString, routes}
import models.ExportedVulnerability
import play.api.libs.json.Json.JsValueWrapper
import play.api.libs.json._
import play.api.libs.ws.{WS, WSClient}
import services.JiraIssueTrackerService.Fields

import scala.concurrent.{ExecutionContext, Future}

private case class JiraNewIssueResponse(id: String, key: String, self: String)

private case class Transition(id: String/* heh, id is a numeric String */, name: String/*to: …*/)

private case class Transitions(expand: String, transitions: Seq[Transition])

object JiraIssueTrackerService {

  final case class Fields(
    cweId: Option[String],
    linkId: Option[String],
    severityId: Option[String],
    projectsId: Option[String],
    /*
    teamsId: Option[String],
    librariesId: Option[String],
    */
    constantFields: Option[JsObject]
  )

  val NoFields = Fields(cweId = None, linkId = None, severityId = None, projectsId = None, constantFields = None)

}

/**
  * status: WIP
  * It basically works, but there is much to be discussed and implemented.
  */
class JiraIssueTrackerService @Inject()(absolutizer: Absolutizer, @Named("jira-server") server: String, noRelevantProjectAffectedTransitionNameOption: Option[String], newProjectAddedTransitionNameOption: Option[String], fields: Fields, @Named("jira-project-id") projectId: Int, @Named("jira-vulnerability-issue-type") vulnerabilityIssueType: Int, ticketFormatVersion: Int, @Named("jira-authentication") atlassianAuthentication: AtlassianAuthentication)(implicit executionContext: ExecutionContext, wSClient: WSClient) extends IssueTrackerService{
  private def jiraUrl(url: String) = atlassianAuthentication.addAuth(WS.clientUrl(url))
  private def api(endpoint: String) = jiraUrl(server+"/rest/api/2/"+endpoint)

  private implicit val TransitionFormats = Json.format[Transition]
  private implicit val TransitionsFormats = Json.format[Transitions]

  override def reportVulnerability(vulnerability: Vulnerability, projects: Set[ReportInfo]): Future[ExportedVulnerability[String]] = api("issue").post(Json.obj(
    "fields" -> (extractInitialFields(vulnerability) ++ extractManagedFields(vulnerability, projects))
  )).map(response => // returns responses like {"id":"1234","key":"PROJ-6","self":"https://…/rest/api/2/issue/1234"}
    try{
      val issueInfo = Json.reads[JiraNewIssueResponse].reads(response.json).get
      ExportedVulnerability(vulnerabilityName = vulnerability.name, ticket = issueInfo.key, ticketFormatVersion = ticketFormatVersion)
    }catch{
      case e:Throwable=>sys.error("bad data: "+response.body)
    }
  )

  override def updateVulnerability(vuln: Vulnerability, diff: SetDiff[ReportInfo], ticket: String): Future[Unit] = {
    val requiredTransitionOption = diff.whichNonEmpty match {
      case SetDiff.Selection.Old => noRelevantProjectAffectedTransitionNameOption
      case SetDiff.Selection.New | SetDiff.Selection.Both => newProjectAddedTransitionNameOption
      case SetDiff.Selection.None => sys.error("this should not happpen")
    }
    val transitionOptionFuture = requiredTransitionOption.map{ requiredTransition =>
      api(s"issue/$ticket/transitions").get().map{resp =>
        assert(resp.status == 200)
        resp.json.validate[Transitions].recover{case e => sys.error(s"Bad JSON: "+e+"\n\n"+resp.json)}.get.transitions.filter(_.name == requiredTransition) match {
          case Seq() => None
          case Seq(i) => Some(i)
        }
      }
    }.getOrElse(Future.successful(None))
    transitionOptionFuture flatMap {transitionOption =>
      val transitionJson = transitionOption.fold(Json.obj())(transition => Json.obj("transition" -> Json.obj("id" -> transition.id)))
      val fieldsJson = Json.obj(
        "fields" -> extractManagedFields(vuln, diff.newSet)
      )
      api(s"issue/$ticket").put(transitionJson ++ fieldsJson).map{ resp =>
        if(resp.status != 204){
          sys.error("Update failed: "+resp.body)
        }
        ()
      }
    }
  }

  private def extractInitialFields(vulnerability: Vulnerability): JsObject = Json.obj(
    "project" -> Json.obj(
      "id" -> projectId.toString
    ),
    "summary" -> s"${vulnerability.name} – ${vulnerability.cweOption.map(_ + ": ").getOrElse("")}${vulnerability.description.take(50)}…"
  )

  private def extractManagedFields(vulnerability: Vulnerability, projects: Set[ReportInfo]): JsObject = {
    val base = Json.obj(
      "issuetype" -> Json.obj(
        "id" -> vulnerabilityIssueType.toString
      ),
      "description" -> extractDescription(vulnerability)
    )
    val additionalFields = Seq[Option[(String, JsValueWrapper)]](
      fields.cweId.map(id => id -> vulnerability.cweOption.fold("")(_.brief)),
      fields.linkId.map(id => id -> link(vulnerability)),
      fields.severityId.map(id => id -> vulnerability.cvssScore),
      fields.projectsId.map(id => id -> projects.map(friendlyProjectNameString).toSeq.sortBy( x => (x.toLowerCase(), x)).mkString("\n"))
      // TODO: add affected releases
    )
    val additionalObj = Json.obj(additionalFields.flatten : _*)
    val constantObj = fields.constantFields.getOrElse(Json.obj())
    base ++ additionalObj ++ constantObj
  }


  /*override def migrateOldIssues(): Future[Unit] = {

  }*/

  private def extractDescription(vulnerability: Vulnerability): String = vulnerability.description + "\n\n" + s"Details: ${link(vulnerability)}"

  private def link(vulnerability: Vulnerability): String = {
    absolutizer.absolutize(routes.Statistics.vulnerability(vulnerability.name, None))
  }

  override def ticketLink(ticket: String): String = s"$server/browse/$ticket"

}
