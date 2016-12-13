
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

    val issueTrackerExportTables = new ExportPlatformTables[String, (String, String, Int, Boolean)](){
      val tableNamePart = "issue_tracker"
      class IssueTrackerVulnerabilities(tag: Tag) extends ExportedVulnerabilities[String, (String, String, Int, Boolean)](tag, tableNamePart){
        def ticket = column[String]("ticket")
        override def base = (vulnerabilityName, ticket, ticketFormatVersion, done) <> ((ExportedVulnerability.apply[String] _).tupled, ExportedVulnerability.unapply[String])
        def idx_ticket = index("idx_ticket", ticket, unique = true)
      }
      class IssueTrackerVulnerabilityProject(tag: Tag) extends ExportedVulnerabilityProjects(tag, tableNamePart)
      override val tickets = TableQuery[IssueTrackerVulnerabilities]
      override val projects: profile.api.TableQuery[_ <: ExportedVulnerabilityProjects] = TableQuery[IssueTrackerVulnerabilityProject]
    }
    type EmailExportedVulnerabilitiesShape = (String, EmailMessageId, Int, Boolean)
    val mailExportTables = new ExportPlatformTables[EmailMessageId, EmailExportedVulnerabilitiesShape](){
      val tableNamePart = "email"
      class EmailExportedVulnerabilities(tag: Tag) extends ExportedVulnerabilities[EmailMessageId, EmailExportedVulnerabilitiesShape](tag, tableNamePart){
        private implicit val mmiMapper = MappedJdbcType.base[EmailMessageId, String](_.messageId, EmailMessageId)
        def messageId = column[EmailMessageId]("message_id")  // Unlike ticket, message id is not required to be unique in order to handle some edge cases like play.mailer.mock = true
        override def base = (vulnerabilityName, messageId, ticketFormatVersion, done) <> ( (ExportedVulnerability.apply[EmailMessageId] _).tupled, ExportedVulnerability.unapply[EmailMessageId])
      }
      class EmailVulnerabilityProject(tag: Tag) extends ExportedVulnerabilityProjects(tag, tableNamePart)

      override val projects = TableQuery[EmailVulnerabilityProject]
      override val tickets = TableQuery[EmailExportedVulnerabilities]
    }

    val diffDbExportTables = new ExportPlatformTables[String, (String, Int, Boolean)] {
      val tableNamePart = "diff_db"
      class DiffDbVulnerabilities(tag: Tag) extends ExportedVulnerabilities[String, (String, Int, Boolean)](tag, tableNamePart){
        override def base: MappedProjection[ExportedVulnerability[String], (String, Int, Boolean)] = (vulnerabilityName, ticketFormatVersion, done) <> (
          ((n: String, v: Int, d: Boolean) => ExportedVulnerability[String](n, n, v, d)).tupled,
          obj => ExportedVulnerability.unapply[String](obj).map{case (n, _, v, d) => (n, v, d)}
        )
      }
      class DiffDbVulnerabilityProject(tag: Tag) extends ExportedVulnerabilityProjects(tag, tableNamePart)

      override val projects = TableQuery[DiffDbVulnerabilityProject]
      override val tickets = TableQuery[DiffDbVulnerabilities]
    }

    /*{
      import profile.SchemaDescription
      val schema = Seq[Any{def schema: SchemaDescription}](
        //notificationDigestStatuses
        //diffDbExportTables, mailExportTables, issueTrackerExportTables
      ).map(_.schema).foldLeft(profile.DDL(Seq(), Seq()))(_ ++ _)

      val sql = Seq(
        "# --- !Ups",
        schema.createStatements.toSeq.map(_+";").mkString("\n").dropWhile(_ == "\n"),
        "",
        "# --- !Downs",
        schema.dropStatements.toSeq.map(_+";").mkString("\n").dropWhile(_ == "\n"),
        "\n"
      ).mkString("\n")
      Files.write(Paths.get("conf/evolutions/default/10.sql"), sql.getBytes("utf-8"))
    }*/

  }

}
