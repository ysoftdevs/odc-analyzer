package services

import scala.concurrent.Future

trait CredentialsVerificationService {
  def verifyCredentials(username: String, password: String): Future[Boolean]
}
