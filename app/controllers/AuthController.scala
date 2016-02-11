package controllers

import javax.inject.Inject

import _root_.services.{UserService, CredentialsVerificationService}
import com.mohiva.play.silhouette.api._
import com.mohiva.play.silhouette.api.util.Clock
import com.mohiva.play.silhouette.impl.authenticators.CookieAuthenticator
import models.User
import play.api.data.Form
import play.api.data.Forms.{email =>_, _}
import play.api.i18n.{Messages, MessagesApi}
import play.api.libs.concurrent.Execution.Implicits._

import scala.concurrent.Future

final case class LoginRequest(username: String, password: String, rememberMe: Boolean)

class AuthController @Inject() (
  val messagesApi: MessagesApi,
  val env: Environment[User, CookieAuthenticator],
  clock: Clock,
  credentialsVerificationService: CredentialsVerificationService,
  userService: UserService
) extends AuthenticatedController {

  val signInForm = Form(mapping(
    "username" -> nonEmptyText,
    "password" -> nonEmptyText,
    "rememberMe" -> boolean
  )(LoginRequest.apply)(LoginRequest.unapply))

  def signIn = UserAwareAction { implicit request =>
    request.identity match {
      case Some(user) => Redirect(routes.Application.index(Map()))
      case None => Ok(views.html.auth.signIn(signInForm/*, socialProviderRegistry*/))
    }
  }

  def authenticate() = UserAwareAction.async { implicit request  =>
    signInForm.bindFromRequest().fold(
      formWithErrors => Future.successful(BadRequest(views.html.auth.signIn(formWithErrors/*, socialProviderRegistry*/))),
      loginRequest => {
        credentialsVerificationService.verifyCredentials(loginRequest.username, loginRequest.password).flatMap{
          case Right(email) =>
            val loginInfo: LoginInfo = LoginInfo(providerID = "credentials-verification", providerKey = email)
            for{
              userOption <- userService.retrieve(loginInfo)
              user = userOption.getOrElse(???)
              authenticator <- env.authenticatorService.create(loginInfo)
              _ = env.eventBus.publish(LoginEvent(user, request, implicitly[Messages]))
              res <- env.authenticatorService.init(authenticator).flatMap(cookie =>
                env.authenticatorService.embed(cookie.copy(secure = request.secure), Redirect(routes.Application.index(Map())))
              )
            } yield res
          case Left(errorMessage) =>
            Future.successful(Redirect(routes.AuthController.signIn()).flashing("error" -> Messages("invalid.credentials")))
        }
      }
    )
  }

  def signOut = SecuredAction.async { implicit request =>
    val result = Redirect(routes.Application.index(Map()))
    env.eventBus.publish(LogoutEvent(request.identity, request, request2Messages))
    env.authenticatorService.discard(request.authenticator, result)
  }
}
