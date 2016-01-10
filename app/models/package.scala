import slick.lifted.TableQuery

/**
 * Created by user on 8/12/15.
 */
package object models {

  val profile = slick.driver.PostgresDriver

  val jodaSupport = com.github.tototoshi.slick.PostgresJodaSupport

  object tables {
    val libraries = TableQuery[Libraries]
    val libraryTagAssignments = TableQuery[LibraryTagAssignments]
    val tags = TableQuery[LibraryTags]
    val snoozesTable = TableQuery[Snoozes]
    val authTokens = TableQuery[CookieAuthenticators]
  }

}
