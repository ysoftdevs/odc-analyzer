package controllers.api

import play.api.libs.Crypto

sealed abstract class ApiApplication {
  def authenticate(appToken: String): Option[AuthenticatedApiApplication]
}

object ApiApplication{
  final class Plain(token: String, authenticatedApiApplication: AuthenticatedApiApplication) extends ApiApplication{
    override def authenticate(appToken: String): Option[AuthenticatedApiApplication] = {
      if(Crypto.constantTimeEquals(appToken, token)) Some(authenticatedApiApplication)
      else None
    }
  }
}
