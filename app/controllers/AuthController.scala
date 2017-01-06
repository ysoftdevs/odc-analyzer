package controllers

import javax.inject.Inject

import _root_.services.{CredentialsVerificationService, UserService}
import com.mohiva.play.silhouette.api._
import com.mohiva.play.silhouette.api.util.Clock
import com.mohiva.play.silhouette.impl.authenticators.CookieAuthenticator
import models.User
import play.api.data.Form
import play.api.data.Forms.{email => _, _}
import play.api.i18n.{Messages, MessagesApi}
import play.api.libs.concurrent.Execution.Implicits._
import play.api.mvc.RequestHeader

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

  def signIn(callback: String) = UserAwareAction { implicit request =>
    request.identity match {
      case Some(user) => generateCallback(callback)
      case None => Ok(views.html.auth.signIn(signInForm, callback/*, socialProviderRegistry*/))
    }
  }

  def authenticate(callback: String) = UserAwareAction.async { implicit request  =>
    signInForm.bindFromRequest().fold(
      formWithErrors => Future.successful(BadRequest(views.html.auth.signIn(formWithErrors, callback/*, socialProviderRegistry*/))),
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
                env.authenticatorService.embed(cookie.copy(secure = request.secure), generateCallback(callback))
              )
            } yield res
          case Left(errorMessage) =>
            Future.successful(Redirect(routes.AuthController.signIn(callback)).flashing("error" -> errorMessage))
        }
      }
    )
  }

  private def generateCallback(callback: String)(implicit hr: RequestHeader) = {
    // Checking slash and adding //host is prevention against open redirect attacks. Just checking the leading slash is not enough, as one might pass callback like “//google.com”.
    if (callback startsWith "/") Redirect("//"+hr.host+callback) else Redirect(routes.Application.index(Map()))
  }

  def signOut(callback: String) = SecuredAction.async { implicit request =>
    val result = generateCallback(callback)
    env.eventBus.publish(LogoutEvent(request.identity, request, request2Messages))
    env.authenticatorService.discard(request.authenticator, result)
  }
}
