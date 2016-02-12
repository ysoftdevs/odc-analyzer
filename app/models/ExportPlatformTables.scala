package models

import models.profile.api._

abstract class ExportPlatformTables[T, U] private[models] () {
  val tickets: TableQuery[_ <: ExportedVulnerabilities[T, U]]
  val projects: TableQuery[_ <: ExportedVulnerabilityProjects]
  def schema = tickets.schema ++ projects.schema
}
