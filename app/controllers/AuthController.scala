package controllers

import javax.inject.Inject

import _root_.services.CredentialsVerificationService
import com.mohiva.play.silhouette.api._
import com.mohiva.play.silhouette.api.util.Clock
import com.mohiva.play.silhouette.impl.authenticators.CookieAuthenticator
import models.User
import play.api.data.Form
import play.api.data.Forms._
import play.api.i18n.{Messages, MessagesApi}
import play.api.libs.concurrent.Execution.Implicits._

import scala.concurrent.Future

final case class LoginRequest(username: String, password: String, rememberMe: Boolean)

class AuthController @Inject() (
  val messagesApi: MessagesApi,
  val env: Environment[User, CookieAuthenticator],
  clock: Clock,
  credentialsVerificationService: CredentialsVerificationService
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
          case true =>
            val loginInfo: LoginInfo = LoginInfo(providerID = "credentials-verification", providerKey = loginRequest.username)
            val user: User = User(username = loginRequest.username)
            env.authenticatorService.create(loginInfo) flatMap { authenticator =>
              env.eventBus.publish(LoginEvent(user, request, implicitly[Messages]))
              env.authenticatorService.init(authenticator).flatMap(cookie =>
                env.authenticatorService.embed(cookie.copy(secure = request.secure), Redirect(routes.Application.index(Map())))
              )
            }
          case false => Future.successful(Redirect(routes.AuthController.signIn()).flashing("error" -> Messages("invalid.credentials")))
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
