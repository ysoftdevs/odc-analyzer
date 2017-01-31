package controllers.api

trait ApiResources {
  val ProjectTable = ApiResource("project-table")
}

object ApiResources extends ApiResources{
  val All = Set(ProjectTable)
  private val AllByName = All.map(res => res.name -> res).toMap
  def byName(name: String): Option[ApiResource] = AllByName.get(name)
}