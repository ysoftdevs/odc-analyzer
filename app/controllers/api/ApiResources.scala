package controllers.api

trait ApiResources {
  val ProjectTable = ApiResource("project-table")
  val Dependencies = ApiResource("dependencies")
  val ScanResults = ApiResource("scan-results")
}

object ApiResources extends ApiResources{
  val All = Set(ProjectTable, Dependencies, ScanResults)
  private val AllByName = All.map(res => res.name -> res).toMap
  def byName(name: String): Option[ApiResource] = AllByName.get(name)
}