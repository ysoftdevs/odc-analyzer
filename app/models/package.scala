
import java.nio.file.{Paths, Files}

import slick.lifted.MappedProjection

import scala.language.reflectiveCalls

package object models {
  val profile = slick.driver.PostgresDriver

  val jodaSupport = com.github.tototoshi.slick.PostgresJodaSupport
  import profile.api._
  import profile.MappedJdbcType


  object tables {
    val libraries = TableQuery[Libraries]
    val libraryTagAssignments = TableQuery[LibraryTagAssignments]
    val tags = TableQuery[LibraryTags]
    val snoozesTable = TableQuery[Snoozes]
    val authTokens = TableQuery[CookieAuthenticators]
    val vulnerabilitySubscriptions = TableQuery[VulnerabilitySubscriptions]
    val changelog = TableQuery[Changes]
    val notificationDigestStatuses = TableQuery[NotificationDigestStatuses]

    val issueTrackerExportTables = new ExportPlatformTables[String, (String, String, Int)](){
      val tableNamePart = "issue_tracker"
      class IssueTrackerVulnerabilities(tag: Tag) extends ExportedVulnerabilities[String, (String, String, Int)](tag, tableNamePart){
        def ticket = column[String]("ticket")
        override def base = (vulnerabilityName, ticket, ticketFormatVersion) <> ((ExportedVulnerability.apply[String] _).tupled, ExportedVulnerability.unapply[String])
        def idx_ticket = index("idx_ticket", ticket, unique = true)
      }
      class IssueTrackerVulnerabilityProject(tag: Tag) extends ExportedVulnerabilityProjects(tag, tableNamePart)
      override val tickets = TableQuery[IssueTrackerVulnerabilities]
      override val projects: profile.api.TableQuery[_ <: ExportedVulnerabilityProjects] = TableQuery[IssueTrackerVulnerabilityProject]
    }
    type EmailExportedVulnerabilitiesShape = (String, EmailMessageId, Int)
    val mailExportTables = new ExportPlatformTables[EmailMessageId, EmailExportedVulnerabilitiesShape](){
      val tableNamePart = "email"
      class EmailExportedVulnerabilities(tag: Tag) extends ExportedVulnerabilities[EmailMessageId, EmailExportedVulnerabilitiesShape](tag, tableNamePart){
        private implicit val mmiMapper = MappedJdbcType.base[EmailMessageId, String](_.messageId, EmailMessageId)
        def messageId = column[EmailMessageId]("message_id")  // Unlike ticket, message id is not required to be unique in order to handle some edge cases like play.mailer.mock = true
        override def base = (vulnerabilityName, messageId, ticketFormatVersion) <> ( (ExportedVulnerability.apply[EmailMessageId] _).tupled, ExportedVulnerability.unapply[EmailMessageId])
      }
      class EmailVulnerabilityProject(tag: Tag) extends ExportedVulnerabilityProjects(tag, tableNamePart)

      override val projects = TableQuery[EmailVulnerabilityProject]
      override val tickets = TableQuery[EmailExportedVulnerabilities]
    }

    val diffDbExportTables = new ExportPlatformTables[String, (String, Int)] {
      val tableNamePart = "diff_db"
      class DiffDbVulnerabilities(tag: Tag) extends ExportedVulnerabilities[String, (String, Int)](tag, tableNamePart){
        override def base: MappedProjection[ExportedVulnerability[String], (String, Int)] = (vulnerabilityName, ticketFormatVersion) <> (
          ((n: String, v: Int) => ExportedVulnerability[String](n, n, v)).tupled,
          obj => ExportedVulnerability.unapply[String](obj).map{case (n, _, v) => (n, v)}
        )
      }
      class DiffDbVulnerabilityProject(tag: Tag) extends ExportedVulnerabilityProjects(tag, tableNamePart)

      override val projects = TableQuery[DiffDbVulnerabilityProject]
      override val tickets = TableQuery[DiffDbVulnerabilities]
    }

    /*{
      import profile.SchemaDescription
      val schema = Seq[Any{def schema: SchemaDescription}](
        notificationDigestStatuses
      ).map(_.schema).foldLeft(profile.DDL(Seq(), Seq()))(_ ++ _)

      val sql = Seq(
        "# --- !Ups",
        schema.createStatements.toSeq.map(_+";").mkString("\n").dropWhile(_ == "\n"),
        "",
        "# --- !Downs",
        schema.dropStatements.toSeq.map(_+";").mkString("\n").dropWhile(_ == "\n"),
        "\n"
      ).mkString("\n")
      Files.write(Paths.get("conf/evolutions/default/8.sql"), sql.getBytes("utf-8"))
    }*/

  }

}
