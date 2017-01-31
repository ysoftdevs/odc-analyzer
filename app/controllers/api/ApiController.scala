package controllers.api

import controllers.AuthenticatedController
import play.api.mvc.{ActionBuilder, Request, Result}
import play.twirl.api.Txt

import scala.concurrent.Future

trait ApiController extends AuthenticatedController with ApiResources {

  protected def apiConfig: ApiConfig

  protected def ApiAction(resource: ApiResource) = new ActionBuilder[Request] {
    override def invokeBlock[A](request: Request[A], block: (Request[A]) => Future[Result]): Future[Result] = {
      val appNameOption = request.headers.get("x-app-name").orElse(request.getQueryString("app-name"))
      val appTokenOption = request.headers.get("x-app-token").orElse(request.getQueryString("app-token"))
      (appNameOption, appTokenOption) match {
        case (Some(appName), Some(appToken)) =>
          apiConfig.getApplication(appName, appToken) match {
            case Some(app) =>
              if(app.isAllowed(resource)) block(request)
              else Future.successful(Unauthorized(Txt("The application is not allowed to access "+resource.name)))
            case None => Future.successful(Unauthorized(Txt("Unknown application or bad token")))
          }
        case _ => Future.successful(Unauthorized(Txt("Missing auth headers x-app-name and x-app-token (or similar GET parameters).")))
      }
    }
  }

}
