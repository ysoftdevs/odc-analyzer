package modules

import javax.inject.Named

import com.google.inject.{AbstractModule, Provides}
import com.ysoft.odc.Absolutizer
import net.ceedubs.ficus.Ficus._
import net.codingwell.scalaguice.ScalaModule
import play.api.Configuration
import play.api.libs.mailer.MailerClient
import services.{EmailExportService, VulnerabilityNotificationService}

import scala.concurrent.ExecutionContext

class EmailExportModule extends AbstractModule with ScalaModule{
  override def configure(): Unit = {
  }

  @Provides
  def provideIssueTrackerOption(conf: Configuration, mailerClient: MailerClient, notificationService: VulnerabilityNotificationService, absolutizer: Absolutizer, @Named("email-sending") emailSendingExecutionContext: ExecutionContext)(implicit executionContext: ExecutionContext): Option[EmailExportService] = {
    println(s"emailSendingExecutionContext = $emailSendingExecutionContext")
    conf.getConfig("yssdc.export.email").map{c =>
      new EmailExportService(
        from = c.underlying.as[String]("from"),
        mailerClient = mailerClient,
        emailSendingExecutionContext = emailSendingExecutionContext,
        absolutizer = absolutizer,
        notificationService = notificationService,
        nobodyInterestedContact = c.underlying.as[String]("noSubscriberContact")
      )
    }
  }
}
