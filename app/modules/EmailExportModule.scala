package modules

import javax.inject.Named

import com.google.inject.{AbstractModule, Provides}
import com.ysoft.odc.Absolutizer
import net.ceedubs.ficus.Ficus._
import net.codingwell.scalaguice.ScalaModule
import play.api.Configuration
import play.api.libs.mailer.MailerClient
import services.{OdcService, EmailExportService, EmailExportType, VulnerabilityNotificationService}
import net.ceedubs.ficus.readers.EnumerationReader._
import scala.concurrent.ExecutionContext

class EmailExportModule extends AbstractModule with ScalaModule{
  override def configure(): Unit = {
  }

  @Provides
  def provideIssueTrackerOption(
                                 conf: Configuration,
                                 mailerClient: MailerClient,
                                 notificationService: VulnerabilityNotificationService,
                                 absolutizer: Absolutizer,
                                 odcService: OdcService,
                                 @Named("email-sending") emailSendingExecutionContext: ExecutionContext
                               )(implicit executionContext: ExecutionContext): Option[EmailExportService] = {
    println(s"emailSendingExecutionContext = $emailSendingExecutionContext")
    conf.getConfig("yssdc.export.email").map{c =>
      new EmailExportService(
        from = c.underlying.as[String]("from"),
        odcService = odcService,
        exportType = c.underlying.getAs[EmailExportType.Value]("type").ensuring{ x => println(x) ; true}.getOrElse(EmailExportType.Vulnerabilities),
        mailerClient = mailerClient,
        emailSendingExecutionContext = emailSendingExecutionContext,
        absolutizer = absolutizer,
        notificationService = notificationService,
        nobodyInterestedContact = c.underlying.as[String]("noSubscriberContact")
      )
    }
  }
}
