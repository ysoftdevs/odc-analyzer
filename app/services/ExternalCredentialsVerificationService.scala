package services

import play.api.libs.json.Json
import play.api.libs.ws.{WS, WSClient}

import scala.concurrent.{Future, ExecutionContext}

class ExternalCredentialsVerificationService(url: String)(implicit executionContext: ExecutionContext, wSClient: WSClient) extends CredentialsVerificationService{
  override def verifyCredentials(username: String, password: String): Future[Boolean] = {
    WS.clientUrl(url).post(Json.toJson(Map("username" -> username, "password" -> password))).map{ response =>
      response.body match {
        case "OK" => true
        case "bad" => false
      }
    }
  }
}
