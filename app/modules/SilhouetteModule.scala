package modules

import com.google.inject.{AbstractModule, Provides}
import com.mohiva.play.silhouette.api.repositories.AuthInfoRepository
import com.mohiva.play.silhouette.api.util._
import com.mohiva.play.silhouette.api.{Environment, EventBus}
import com.mohiva.play.silhouette.api.services.AuthenticatorService
import com.mohiva.play.silhouette.impl.authenticators.{CookieAuthenticatorService, CookieAuthenticatorSettings, CookieAuthenticator}
import com.mohiva.play.silhouette.impl.daos.DelegableAuthInfoDAO
import com.mohiva.play.silhouette.impl.providers.{CredentialsProvider, SocialProviderRegistry}
import com.mohiva.play.silhouette.impl.repositories.DelegableAuthInfoRepository
import com.mohiva.play.silhouette.impl.util.{BCryptPasswordHasher, SecureRandomIDGenerator, DefaultFingerprintGenerator}
import models.User
import net.codingwell.scalaguice.ScalaModule
import play.api.libs.ws.WSClient
import play.api.{Application, Configuration}
import services._
import net.ceedubs.ficus.Ficus._
import net.ceedubs.ficus.readers.ArbitraryTypeReader._
import play.api.libs.concurrent.Execution.Implicits._

class SilhouetteModule extends AbstractModule with ScalaModule{


  override def configure(): Unit = {
    bind[FingerprintGenerator].toInstance(new DefaultFingerprintGenerator(false))
    bind[IDGenerator].toInstance(new SecureRandomIDGenerator())
    bind[Clock].toInstance(Clock())
  }

  @Provides
  def provideAuthInfoRepository(passwordInfoDAO: DelegableAuthInfoDAO[PasswordInfo]): AuthInfoRepository = {
    new DelegableAuthInfoRepository(passwordInfoDAO)
  }

  @Provides
  def provideAuthenticatorService(
                                   fingerprintGenerator: FingerprintGenerator,
                                   idGenerator: IDGenerator,
                                   configuration: Configuration,
                                   clock: Clock,
                                   tokenService: TokenService
                                 ): AuthenticatorService[CookieAuthenticator] = {
    val config = configuration.underlying.as[CookieAuthenticatorSettings]("silhouette.authenticator")
    new CookieAuthenticatorService(
      config,
      Some(tokenService),
      fingerprintGenerator,
      idGenerator,
      clock
    )
  }

  @Provides
  def provideCredentialsVerificationService(configuration: Configuration, app: Application)(implicit wSClient: WSClient): CredentialsVerificationService = {
    configuration.underlying.as[String]("silhouette.credentialsVerificationService.type") match {
      case "allow-all" => new AllowAllCredentialsVerificationService(app)
      case "external" => new ExternalCredentialsVerificationService(configuration.underlying.as[String]("silhouette.credentialsVerificationService.url"))
    }
  }

  @Provides
  def provide(userService: UserService): DelegableAuthInfoDAO[PasswordInfo] = userService

  @Provides
  def provideEnvironment(
                          userService: UserService,
                          authenticatorService: AuthenticatorService[CookieAuthenticator],
                          eventBus: EventBus): Environment[User, CookieAuthenticator] = {
    Environment[User, CookieAuthenticator](
      userService,
      authenticatorService,
      Seq(),
      eventBus
    )
  }

}
