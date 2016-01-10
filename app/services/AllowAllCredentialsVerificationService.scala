package services

import scala.concurrent.Future

class AllowAllCredentialsVerificationService(app: play.api.Application) extends CredentialsVerificationService{
  if(app.mode != play.api.Mode.Dev){
    // safety check:
    sys.error("allow-all can be used in dev mode only")
  }

  override def verifyCredentials(username: String, password: String): Future[Boolean] = Future.successful(true)

}
