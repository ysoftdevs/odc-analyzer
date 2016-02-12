package controllers

import com.mohiva.play.silhouette.api.Silhouette
import com.mohiva.play.silhouette.impl.authenticators.CookieAuthenticator
import models.User
import play.api.mvc.{Result, RequestHeader, Results}
import views.html.DefaultRequest

import scala.concurrent.Future
import scala.language.implicitConversions

trait AuthenticatedControllerLowPriorityImplicits[T, C]{
  self: AuthenticatedController =>

  protected object secureRequestConversion{
    implicit def securedRequestToUserAwareRequest(implicit req: SecuredRequest[_]): DefaultRequest = UserAwareRequest(Some(req.identity), authenticator = Some(req.authenticator), req.request)
  }
}

abstract class AuthenticatedController extends Silhouette[User, CookieAuthenticator] with AuthenticatedControllerLowPriorityImplicits[User, CookieAuthenticator]{


  override protected def onNotAuthenticated(request: RequestHeader): Option[Future[Result]] = Some(Future.successful(Redirect(
    routes.AuthController.signIn(request.path+"?"+request.rawQueryString)
  )))

  object ReadAction extends SecuredActionBuilder with Results {

  }

  def AdminAction: SecuredActionBuilder = ???

}