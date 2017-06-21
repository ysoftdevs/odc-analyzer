package controllers

import com.mohiva.play.silhouette.api.Silhouette
import com.mohiva.play.silhouette.impl.authenticators.CookieAuthenticator
import com.typesafe.config.Config
import models.User
import modules.TemplateCustomization
import play.api.mvc.{RequestHeader, Result, Results}
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

  protected implicit def templateCustomization: TemplateCustomization

  override protected def onNotAuthenticated(request: RequestHeader): Option[Future[Result]] = Some(Future.successful(Redirect(
    routes.AuthController.signIn(request.path+"?"+request.rawQueryString)
  )))

  object ReadAction extends SecuredActionBuilder with Results {

  }

  def AdminAction: SecuredActionBuilder = ???

  protected implicit def mainTemplateData: MainTemplateData = MainTemplateData.createMainTemplateData

}