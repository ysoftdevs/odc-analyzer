package services

import play.api.libs.json.Json
import play.api.libs.ws.{WS, WSClient}

import scala.concurrent.{Future, ExecutionContext}

case class LoginResponse(error: Option[String], email: Option[String])

class ExternalCredentialsVerificationService(url: String)(implicit executionContext: ExecutionContext, wSClient: WSClient) extends CredentialsVerificationService{

  private implicit val loginResponseFormat = Json.format[LoginResponse]

  override def verifyCredentials(username: String, password: String): Future[Either[String, String]] = {
    WS.clientUrl(url).post(Json.toJson(Map("username" -> username, "password" -> password))).map{ response =>
      val loginResponse = loginResponseFormat.reads(response.json).get
      loginResponse.error match {
        case Some(err) => Left(err)
        case None => Right(loginResponse.email.get)
      }
    }
  }
}
