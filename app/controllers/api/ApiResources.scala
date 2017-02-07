package controllers.api

trait ApiResources {
  val ProjectTable = ApiResource("project-table")
  val Dependencies = ApiResource("dependencies")
}

object ApiResources extends ApiResources{
  val All = Set(ProjectTable, Dependencies)
  private val AllByName = All.map(res => res.name -> res).toMap
  def byName(name: String): Option[ApiResource] = AllByName.get(name)
}